# SSH Log Security Analyzer

A Python cybersecurity project for analyzing SSH authentication logs and detecting suspicious activity such as brute-force attacks, repeated failed logins, multiple-account targeting, and successful logins following suspicious activity.

## Overview

SSH authentication logs contain valuable information for identifying suspicious access attempts.

This project parses SSH authentication logs, extracts security-relevant events, and applies detection rules to identify potentially malicious activity.

The analyzer also correlates multiple events to detect a potentially successful brute-force attack.

The project was developed as a practical cybersecurity and Python project, with a focus on log analysis, threat detection, event correlation, and automated testing.

## Features

- Parse SSH authentication logs
- Detect failed SSH login attempts
- Detect successful SSH logins
- Extract source IP addresses
- Extract targeted usernames
- Track failed attempts by IP address
- Track failed attempts by username
- Analyze timestamps of authentication attempts
- Detect potential brute-force attacks
- Detect successful logins following multiple failures
- Detect attacks targeting multiple usernames
- Correlate brute-force activity with a subsequent successful login
- Assign severity levels to detected threats
- Handle missing or inaccessible log files
- Automated testing with pytest

## Detection Rules

### Brute-force Detection

The analyzer detects five or more failed authentication attempts from the same source within a short time window.

Example:

    [HIGH] BRUTE_FORCE
           Source IP: 192.168.1.60
           Target user: admin
           Attempts: 5
           Time window: 12 seconds

### Successful Login After Multiple Failures

The analyzer detects a successful authentication following multiple failed attempts from the same source.

Example:

    [HIGH] SUCCESS_AFTER_FAILURES
           Source IP: 192.168.1.30
           Target user: john
           Failed attempts: 3
           Time: 18:05:20

### Multiple Users Targeted

The analyzer can identify a source IP attempting to authenticate against multiple usernames.

Example:

    [MEDIUM] MULTIPLE_USERS
            Source IP: 192.168.1.40
            User count: 3
            Users: admin, guest, root

### Brute-force Followed by Successful Login

The analyzer correlates authentication events and increases the severity when a successful login follows a detected brute-force pattern.

Example:

    [CRITICAL] BRUTE_FORCE_SUCCESS
           Source IP: 192.168.1.70
           Target user: admin
           Failed attempts: 5
           Time window: 8 seconds
           Successful login: 18:11:15

## Project Structure

    python-log-analyzer/
    │
    ├── log_analyzer.py
    ├── sample_auth.log
    ├── .gitignore
    ├── README.md
    │
    └── tests/
        ├── __init__.py
        └── test_log_analyzer.py

## Technologies

- Python 3
- Regular Expressions
- datetime
- pytest
- Git / GitHub

## Installation

Clone the repository:

    git clone https://github.com/YOUR_USERNAME/python-log-analyzer.git
    cd python-log-analyzer

Create a virtual environment:

    python -m venv .venv

Activate the virtual environment.

### Windows PowerShell

    .\.venv\Scripts\Activate.ps1

Install the testing dependency:

    python -m pip install pytest

## Usage

Run the analyzer:

    python log_analyzer.py

The analyzer reads the sample SSH authentication log and generates a security report in the terminal.

## Testing

The project includes automated tests covering the main detection rules and error handling.

Run the test suite:

    pytest

The current test suite covers:

- Brute-force detection
- Negative brute-force scenarios
- Successful login after multiple failures
- Negative successful-login scenarios
- Multiple-user targeting
- Negative multiple-user scenarios
- Brute-force followed by successful login
- Negative correlation scenarios
- Log file reading
- Missing log file handling

## Example Output

    ========================================
            SSH LOG SECURITY ANALYZER
    ========================================

    Total events       : 23
    Successful logins  : 4
    Failed logins      : 19

    ----------------------------------------
    TOP SOURCE IPs
    ----------------------------------------
    192.168.1.60     8 failed attempts
    192.168.1.15     2 failed attempts
    192.168.1.30     4 failed attempts
    192.168.1.40     3 failed attempts
    192.168.1.70     6 failed attempts

    ----------------------------------------
    TARGETED USERS
    ----------------------------------------
    admin            13 failed attempts
    john              6 failed attempts
    test              2 failed attempts
    root              1 failed attempts
    guest             1 failed attempts

    ----------------------------------------
    SECURITY ALERTS
    ----------------------------------------
    [CRITICAL] BRUTE_FORCE_SUCCESS
           Source IP: 192.168.1.70
           Target user: admin
           Failed attempts: 5
           Time window: 8 seconds
           Successful login: 18:11:15

    [HIGH] BRUTE_FORCE
           Source IP: 192.168.1.60
           Target user: admin
           Attempts: 5
           Time window: 12 seconds

    [HIGH] SUCCESS_AFTER_FAILURES
           Source IP: 192.168.1.30
           Target user: john
           Failed attempts: 3
           Time: 18:05:20

    [MEDIUM] MULTIPLE_USERS
            Source IP: 192.168.1.40
            User count: 3
            Users: admin, guest, root

## Security Considerations

This project is intended for educational purposes and controlled environments.

The included sample_auth.log contains simulated authentication events and does not contain real credentials or production log data.

The analyzer performs detection based on predefined rules and should not be considered a replacement for a production SIEM or intrusion detection system.

## Future Improvements

Planned improvements include:

- JSON export of detected security events
- CSV export
- Improved event correlation
- Additional detection rules
- Configurable detection thresholds
- Support for additional log formats
- Improved unit test coverage
- Potential web interface for visualizing security events

## Learning Objectives

This project was developed to practice:

- Python programming
- Regular expressions
- Log parsing
- Security event analysis
- Threat detection
- Event correlation
- Defensive cybersecurity concepts
- Automated testing
- Git and GitHub workflow

## Author

Developed as part of a cybersecurity career transition and practical learning projects.