# Gmail Folder Reader and Excel Exporter

This project provides a script to read emails from a specified folder in Gmail and export the data to an Excel file. The extracted data includes the sender, a short description of the email, and the date. Additionally, the script attempts to determine the sender's company name from the email domain, subject, or body.

## Setup Instructions

### Prerequisites

- Python 3.x
- A Google account with Gmail access
- Access to the Google Cloud Console

### Setting up the Gmail API

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project or select an existing project.
3. Enable the Gmail API for the project.
4. Create OAuth 2.0 credentials for the project.
5. Download the `credentials.json` file and save it in the project directory.

### Installing Required Libraries

Install the required Python libraries using `pip`:

```sh
pip install -r requirements.txt
```

### Running the Script

1. Ensure the `credentials.json` file is in the project directory.
2. Run the script:

```sh
python src/gmail_extractor.py
```

The script will read emails from the specified folder in Gmail and export the data to an Excel file named `emails.xlsx`.
