# Data Setup Guide

## What data do you need to download?

For the current version of this project, you do not need to download any external dataset.

The project already includes all required input files in:

- `data/sample_logs/auth_logs.csv`
- `data/sample_logs/process_logs.csv`
- `data/sample_logs/network_logs.csv`

These three CSV files are the data sources loaded by `main.py`.

## What each file contains

### `auth_logs.csv`
Required columns:

- `timestamp`
- `username`
- `source_ip`
- `host`
- `event_type`
- `status`

### `process_logs.csv`
Required columns:

- `timestamp`
- `host`
- `username`
- `process_name`
- `parent_process`
- `command_line`

### `network_logs.csv`
Required columns:

- `timestamp`
- `host`
- `source_ip`
- `destination_ip`
- `destination_port`
- `protocol`

## Easiest way to get the data

### Option 1: Clone the repository

If you clone or download this repository, the sample data comes with it automatically.

```bash
git clone <repo-url>
cd ThreatHuntingEngine
```

After that, the data is already available under `data/sample_logs/`.

### Option 2: Download the repository as ZIP

If you download the project as a ZIP file and extract it, make sure this folder exists:

```text
data/sample_logs/
```

And make sure it contains the three CSV files listed above.

## How to run the project easily

1. Install Python dependencies:

```bash
pip3 install -r requirements.txt
```

2. Run the project from the repository root:

```bash
python3 main.py
```

## If you want to use your own data

Replace the sample CSV files with your own files, but keep:

- the same file names, or update the paths in `main.py`
- the same required column names shown above

If a required column is missing, the parser will raise an error.
