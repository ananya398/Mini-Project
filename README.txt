# CVE Severity Predictor - Windows Package

## Contents
- Updated Streamlit app with dashboard styling
- Random Forest severity prediction models
- BERT severity classification model
- BERT CVSS score regression model
- CVE dataset used for dashboard statistics
- Windows setup and launch scripts

## Requirements
- Windows 10 or Windows 11, 64-bit
- Python 3.10 or 3.11, 64-bit
- Internet access for first-time dependency installation and CVE lookup

## First-time setup
1. Extract the complete ZIP to a normal folder, for example:
   `C:\CVE_Project_Windows`
2. Install Python 3.11 (64-bit) if it is not already installed:
   https://www.python.org/downloads/windows/
3. During Python installation, enable "Add Python to PATH".
4. Double-click `setup_windows.bat`.
5. Wait for all packages to install.

## Launch
1. Double-click `run_project.bat`.
2. Wait for Streamlit to start and open the browser.
3. If the browser does not open automatically, visit:
   http://localhost:8501
4. Keep the command window open while using the app.

## Troubleshooting
- If setup fails, check the Python version and internet connection.
- If package installation fails, copy the complete error message.
- Do not move or delete the `models` or `dataset` folders.
- The first launch may take some time while BERT weights are loaded.
- CPU inference works but can be slower than GPU inference.
- NVD lookup requires internet access.
- Model predictions are estimates and are not a substitute for official CVSS assessments.

## Included data
The dashboard uses the included NVD-CVE-ML-Dataset.csv file for its statistics.
The package does not include training checkpoints or raw yearly NVD JSON archives.
