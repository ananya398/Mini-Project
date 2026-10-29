import re
from pathlib import Path

import joblib
import requests
import streamlit as st
import pandas as pd
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

ROOT = Path(__file__).resolve().parent
MODELS = ROOT / "models"

st.set_page_config(
    page_title="CVE Severity Predictor",
    page_icon="🛡️",
    layout="wide"
)


# DASHBOARD_REDESIGN_V1
st.markdown("""
<style>
    .stApp {
        background: #101014;
        color: #ececf2;
    }
    [data-testid="stSidebar"] {
        background: #17171e;
        border-right: 1px solid #292832;
    }
    [data-testid="stHeader"] {
        background: rgba(16, 16, 20, 0.96);
    }
    h1, h2, h3 {
        color: #f4f2fa !important;
        letter-spacing: -0.4px;
    }
    [data-testid="stMetric"] {
        background: #1a1a23;
        border: 1px solid #302d3c;
        padding: 18px 20px;
        border-radius: 13px;
    }
    [data-testid="stMetricLabel"] {
        color: #aaa7ba !important;
    }
    [data-testid="stMetricValue"] {
        color: #f4f0ff !important;
    }
    div.stButton > button[kind="primary"] {
        background: #7956d8;
        border: 1px solid #8b6be8;
        color: white;
        border-radius: 9px;
    }
    div.stButton > button[kind="primary"]:hover {
        background: #6844c7;
        border-color: #a38af0;
    }
    [data-testid="stDataFrame"] {
        border: 1px solid #302d3c;
        border-radius: 10px;
        overflow: hidden;
    }
    div[data-testid="stVerticalBlockBorderWrapper"] {
        border-color: #302d3c;
    }
    hr {
        border-color: #302d3c;
    }
    .dashboard-eyebrow {
        color: #a991f2;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 1.7px;
        text-transform: uppercase;
    }
    .dashboard-subtitle {
        color: #aaa7ba;
        margin-top: -10px;
        margin-bottom: 22px;
    }
</style>
""", unsafe_allow_html=True)



@st.cache_resource
def load_models():
    return {
        "description_model": joblib.load(
            MODELS / "random_forest_description_model.joblib"
        ),
        "description_vectorizer": joblib.load(
            MODELS / "random_forest_description_vectorizer.joblib"
        ),
        "cwe_model": joblib.load(
            MODELS / "random_forest_cwe_model.joblib"
        ),
        "cwe_vectorizer": joblib.load(
            MODELS / "random_forest_cwe_vectorizer.joblib"
        )
    }



@st.cache_resource
def load_bert_models():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    cls_path = MODELS / "cvss_classification_model"
    reg_path = MODELS / "cvss_regression_model"

    cls_tokenizer = AutoTokenizer.from_pretrained(str(cls_path))
    cls_model = AutoModelForSequenceClassification.from_pretrained(str(cls_path))
    cls_model.to(device).eval()

    reg_tokenizer = AutoTokenizer.from_pretrained(str(reg_path))
    reg_model = AutoModelForSequenceClassification.from_pretrained(str(reg_path))
    reg_model.to(device).eval()

    return {
        "device": device,
        "cls_tokenizer": cls_tokenizer,
        "cls_model": cls_model,
        "reg_tokenizer": reg_tokenizer,
        "reg_model": reg_model,
    }


def predict_bert(bert_models, description):
    device = bert_models["device"]

    cls_inputs = bert_models["cls_tokenizer"](
        description, return_tensors="pt",
        truncation=True, padding=True, max_length=256
    )
    cls_inputs = {k: v.to(device) for k, v in cls_inputs.items()}

    with torch.inference_mode():
        logits = bert_models["cls_model"](**cls_inputs).logits
        probs = torch.softmax(logits, dim=-1)[0]
        index = int(torch.argmax(probs).item())
        confidence = float(probs[index].item())

    config = bert_models["cls_model"].config
    label = config.id2label.get(index, f"LABEL_{index}")

    if label.upper().startswith("LABEL_"):
        label = ["LOW", "MEDIUM", "HIGH", "CRITICAL"][index]
    else:
        label = label.upper()

    reg_inputs = bert_models["reg_tokenizer"](
        description, return_tensors="pt",
        truncation=True, padding=True, max_length=256
    )
    reg_inputs = {k: v.to(device) for k, v in reg_inputs.items()}

    with torch.inference_mode():
        score = float(
            bert_models["reg_model"](**reg_inputs).logits.reshape(-1)[0].item()
        )

    return {
        "severity": label,
        "confidence": confidence,
        "cvss_score": max(0.0, min(10.0, score)),
    }




@st.cache_data(show_spinner=False)
def load_dashboard_data():
    dataset_path = ROOT / "dataset" / "NVD-CVE-ML-Dataset.csv"
    if not dataset_path.exists():
        return pd.DataFrame()

    wanted = [
        "CVE_ID", "Description", "CWE", "CVSS_Score",
        "Severity", "CVSS_Vector", "Published"
    ]
    header = pd.read_csv(dataset_path, nrows=0).columns.tolist()
    usecols = [c for c in wanted if c in header]
    if not usecols:
        return pd.DataFrame()
    return pd.read_csv(dataset_path, usecols=usecols)


def fetch_cve(cve_id):
    response = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": cve_id},
        timeout=30
    )
    response.raise_for_status()
    items = response.json().get("vulnerabilities", [])
    if not items:
        return None

    cve = items[0]["cve"]
    description = next(
        (x.get("value", "") for x in cve.get("descriptions", [])
         if x.get("lang") == "en"),
        ""
    )

    cwe = "CWE-UNKNOWN"
    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            value = item.get("value", "")
            if re.fullmatch(r"CWE-\d+", value):
                cwe = value
                break
        if cwe != "CWE-UNKNOWN":
            break

    score, version = None, None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31",
                "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score, version = data.get("baseScore"), data.get("version")
            if score is not None:
                break

    return {
        "id": cve.get("id", cve_id),
        "description": description,
        "cwe": cwe,
        "score": score,
        "version": version,
        "published": cve.get("published", "Unavailable")
    }

def predict(model, vectorizer, text):
    features = vectorizer.transform([text])
    label = model.predict(features)[0]
    confidence = None
    if hasattr(model, "predict_proba"):
        confidence = float(max(model.predict_proba(features)[0]))
    return str(label), confidence

st.title("CVE Severity Prediction")
st.caption("Machine learning-based vulnerability severity analysis")

st.info(
    "Predictions are estimates from trained models. They do not replace "
    "official NVD CVSS assessments or expert security analysis."
)

try:
    models = load_models()
except Exception as exc:
    st.error(f"Could not load the saved models: {exc}")
    st.stop()

try:
    bert_models = load_bert_models()
    bert_load_error = None
except Exception as exc:
    bert_models = None
    bert_load_error = str(exc)


# Dashboard overview
st.sidebar.markdown("## CVE INTELLIGENCE")
st.sidebar.caption("Vulnerability analysis workspace")
st.sidebar.markdown("---")
st.sidebar.markdown("**Overview**")
st.sidebar.caption("Severity prediction")
st.sidebar.caption("CVE lookup")
st.sidebar.caption("Model comparison")
st.sidebar.markdown("---")
st.sidebar.caption("Models: Random Forest + BERT")

st.markdown('<div class="dashboard-eyebrow">SECURITY ANALYTICS / OVERVIEW</div>',
            unsafe_allow_html=True)
st.title("Vulnerability Intelligence")
st.markdown(
    '<div class="dashboard-subtitle">'
    'CVE severity analysis and machine-learning predictions'
    '</div>',
    unsafe_allow_html=True
)

dashboard_df = load_dashboard_data()

if not dashboard_df.empty and "Severity" in dashboard_df.columns:
    severity_counts = (
        dashboard_df["Severity"].fillna("Unknown").astype(str)
        .str.upper().value_counts()
    )
    total_cves = len(dashboard_df)
    critical_count = int(severity_counts.get("CRITICAL", 0))
    high_count = int(severity_counts.get("HIGH", 0))
    medium_count = int(severity_counts.get("MEDIUM", 0))
    low_count = int(severity_counts.get("LOW", 0))

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("TOTAL CVE RECORDS", f"{total_cves:,}")
    k2.metric("CRITICAL", f"{critical_count:,}")
    k3.metric("HIGH SEVERITY", f"{high_count:,}")
    k4.metric("MEDIUM + LOW", f"{medium_count + low_count:,}")

    st.markdown("")
    panel_left, panel_right = st.columns([1.65, 1])

    with panel_left:
        st.subheader("Vulnerability records")
        st.caption("Records from the project dataset")
        display_columns = [
            c for c in ["CVE_ID", "Severity", "CVSS_Score", "CWE", "Published"]
            if c in dashboard_df.columns
        ]
        table_df = dashboard_df[display_columns].copy()

        if "Published" in table_df.columns:
            table_df = table_df.sort_values(
                "Published", ascending=False, na_position="last"
            )
        st.dataframe(
            table_df.head(10),
            use_container_width=True,
            hide_index=True
        )

    with panel_right:
        st.subheader("Severity distribution")
        st.caption("Dataset records by severity")
        chart_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        chart_df = pd.DataFrame({
            "Severity": chart_order,
            "Records": [int(severity_counts.get(s, 0)) for s in chart_order]
        })
        st.bar_chart(
            chart_df.set_index("Severity"),
            use_container_width=True
        )
        st.caption(
            "Distribution reflects the dataset, not live threat activity."
        )
else:
    st.warning("Dataset statistics are unavailable. Check the project CSV path.")

st.divider()
st.subheader("Predict a vulnerability")
st.caption("Search by CVE ID or enter a description to compare model predictions.")

mode = st.radio(
    "Choose input method",
    ["Search by CVE ID", "Enter description manually"],
    horizontal=True
)

if "cve_result" not in st.session_state:
    st.session_state.cve_result = None

if mode == "Search by CVE ID":
    cve_id = st.text_input(
        "CVE ID",
        placeholder="CVE-2024-44290"
    ).strip().upper()

    if st.button("Fetch from NVD"):
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            st.error("Enter a valid CVE ID.")
        else:
            try:
                with st.spinner("Contacting the NVD API..."):
                    result = fetch_cve(cve_id)
                if result is None:
                    st.session_state.cve_result = None
                    st.warning("No matching CVE was returned.")
                elif not result["description"]:
                    st.session_state.cve_result = None
                    st.warning("No English description was available.")
                else:
                    st.session_state.cve_result = result
            except requests.RequestException as exc:
                st.error(f"NVD request failed: {exc}")

    result = st.session_state.cve_result
    description = result["description"] if result else ""
    cwe = result["cwe"] if result else "CWE-UNKNOWN"

    if result:
        st.success(f"Retrieved {result['id']}")
        st.write("**Published:**", result["published"])
        st.write("**CWE:**", cwe)
        st.write("**Official NVD CVSS score:**", result["score"])
        st.text_area("NVD description", description, height=130, disabled=True)

else:
    description = st.text_area(
        "Vulnerability description",
        height=150,
        placeholder="Enter the vulnerability description..."
    )
    cwe = st.text_input("CWE identifier (optional)", "CWE-UNKNOWN")
    cwe = cwe.strip().upper() or "CWE-UNKNOWN"

    if cwe != "CWE-UNKNOWN" and not re.fullmatch(r"CWE-\d+", cwe):
        st.warning("Use a CWE such as CWE-79, or CWE-UNKNOWN.")

st.divider()

if st.button("Predict Severity", type="primary"):
    if not description.strip():
        st.error("Fetch a CVE or enter a description first.")
    elif cwe != "CWE-UNKNOWN" and not re.fullmatch(r"CWE-\d+", cwe):
        st.error("The CWE identifier format is invalid.")
    else:
        desc_label, desc_conf = predict(
            models["description_model"],
            models["description_vectorizer"],
            description
        )
        combined = f"{description} CWE: {cwe}"
        cwe_label, cwe_conf = predict(
            models["cwe_model"],
            models["cwe_vectorizer"],
            combined
        )

        bert_result = None
        if bert_models is not None:
            try:
                bert_result = predict_bert(bert_models, description)
            except Exception as exc:
                st.warning(f"BERT prediction failed: {exc}")

        left, right = st.columns(2)
        with left:
            st.subheader("Description-only model")
            st.metric("Predicted severity", desc_label)
            if desc_conf is not None:
                st.metric("Maximum class probability", f"{desc_conf:.1%}")
        with right:
            st.subheader("Description + CWE model")
            st.metric("Predicted severity", cwe_label)
            if cwe_conf is not None:
                st.metric("Maximum class probability", f"{cwe_conf:.1%}")

        st.divider()
        st.subheader("BERT models")

        if bert_result is not None:
            b1, b2, b3 = st.columns(3)
            b1.metric("BERT severity", bert_result["severity"])
            b2.metric("Classification confidence",
                      f'{bert_result["confidence"]:.1%}')
            b3.metric("Predicted CVSS score",
                      f'{bert_result["cvss_score"]:.2f} / 10')
        elif bert_load_error:
            st.warning(f"BERT models could not be loaded: {bert_load_error}")

        st.caption(
            "Model probability is not a guarantee of correctness. "
            "The two models may disagree."
        )
        if mode == "Search by CVE ID" and st.session_state.cve_result:
            result = st.session_state.cve_result
            st.write("**Official NVD CVSS score:**", result["score"])
            st.write("**CVSS version:**", result["version"])
            st.write(
                "The model prediction and official CVSS rating may differ "
                "because they are produced by different methods."
            )
