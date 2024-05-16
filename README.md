
# Website Script Scanner

## Overview
This Python script scans websites for JavaScript files, creates a baseline of these scripts, and generates an HTML report highlighting any changes or updates to the scripts and headers of the scanned websites. This is particularly useful for maintaining the integrity and security of web assets, especially in environments requiring strict change management and script integrity verification, such as PCI DSS compliance.

## Features
- **Baseline Scanning**: Scan and save the current state of JavaScript files and headers for future comparison.
- **Change Detection**: Identify new, changed, and removed scripts as well as header changes.
- **Content Security Policy (CSP) Detection**: Check if a website has a Content-Security-Policy header.
- **HTML Report Generation**: Generate a detailed HTML report summarizing the changes detected.
- **User Interaction**: Prompt users to authorize new scripts and provide justification.

## Requirements
- Python 3.x
- `requests` library
- `beautifulsoup4` library

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/website-script-scanner.git
    cd website-script-scanner
    ```
2. Install the required libraries:
    ```bash
    pip install requests beautifulsoup4
    ```

## Usage
Run the script using Python:
```bash
python script_scanner.py
```

### Menu Options
1. **Input list of websites**: Enter a comma-separated list of websites to scan.
2. **Perform baseline scan**: Scan the provided websites and save the current state of scripts and headers.
3. **Scan for changes**: Compare the current state of the websites with the baseline and detect any changes.
4. **Exit**: Exit the script.

### Functions
- **`add_scheme_if_missing(url, base_url)`**: Ensures that a URL has a proper scheme (`http://` or `https://`). If missing, it appends the scheme.
- **`validate_url(url)`**: Validates a URL to ensure it has a scheme and netloc (network location).
- **`get_scripts_and_headers(url)`**: Fetches the webpage at the given URL, parses its content to find all `<script>` tags, and computes SHA-256 hashes of the scripts' contents. It also retrieves the response headers.
- **`has_csp(headers)`**: Checks if the 'Content-Security-Policy' header is present in the headers.
- **`save_baseline(baseline_data)`**: Saves the baseline data to a JSON file.
- **`load_baseline()`**: Loads the baseline data from a JSON file.
- **`compare_data(baseline, current)`**: Compares the current scripts and headers with the baseline to detect new, changed, or removed scripts, as well as changes in headers.
- **`prompt_authorization(script_info)`**: Prompts the user to authorize new scripts, asking for justification for each script.
- **`generate_html_report(websites, changes_summary, details, baseline_data, csp_data)`**: Generates an HTML report summarizing the changes detected, providing details on new, changed, and removed scripts, as well as header changes.
- **`display_results(changes_summary, details, baseline_data, csp_data)`**: Displays the results of the scan in the console.

## Example
1. **Input list of websites**: `https://example.com, https://anotherexample.com`
2. **Perform baseline scan**:
    - The script will fetch scripts from the provided websites.
    - You will be prompted to authorize each script and provide justification.
    - Baseline data will be saved in `baseline_scripts.json`.
3. **Scan for changes**:
    - The script will fetch the current state of the websites and compare it with the baseline.
    - An HTML report (`scan_report.html`) will be generated, summarizing the changes.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License
This project is licensed under the MIT License. See the (LICENSE) file for details.
