import requests
from bs4 import BeautifulSoup
import hashlib
import json
import os
from datetime import datetime
from urllib.parse import urlparse

BASELINE_FILE = 'baseline_scripts.json'
REPORT_FILE = 'scan_report.html'


def add_scheme_if_missing(url, base_url):
    if url.startswith('//'):
        return 'https:' + url
    elif not url.startswith(('http://', 'https://')):
        return base_url + url
    return url


def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def get_scripts_and_headers(url):
    response = requests.get(url)
    base_url = '{uri.scheme}://{uri.netloc}/'.format(uri=urlparse(url))
    soup = BeautifulSoup(response.content, 'html.parser')
    scripts = soup.find_all('script')
    script_info = []
    for script in scripts:
        src = script.get('src')
        if src:
            full_url = add_scheme_if_missing(src, base_url)
            try:
                script_response = requests.get(full_url)
                script_content = script_response.text
                script_hash = hashlib.sha256(script_content.encode('utf-8')).hexdigest()
                script_info.append({'src': full_url, 'hash': script_hash})
            except requests.RequestException as e:
                print(f"Failed to fetch script {full_url}: {e}")
    headers = dict(response.headers)
    return script_info, headers


def has_csp(headers):
    return 'Content-Security-Policy' in headers


def save_baseline(baseline_data):
    with open(BASELINE_FILE, 'w') as file:
        json.dump(baseline_data, file, indent=4)


def load_baseline():
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, 'r') as file:
            return json.load(file)
    return {}


def compare_data(baseline, current):
    baseline_scripts = {script['src']: script['hash'] for script in baseline['scripts']}
    current_scripts = {script['src']: script['hash'] for script in current['scripts']}

    changes_detected = False
    changes = {
        'new_scripts': [],
        'changed_scripts': [],
        'removed_scripts': [],
        'header_changes': []
    }

    for src, hash in current_scripts.items():
        if src not in baseline_scripts:
            changes['new_scripts'].append(src)
            changes_detected = True
        elif baseline_scripts[src] != hash:
            changes['changed_scripts'].append(src)
            changes_detected = True

    for src in baseline_scripts:
        if src not in current_scripts:
            changes['removed_scripts'].append(src)
            changes_detected = True

    # Check for changes in headers
    for key, value in current['headers'].items():
        if key not in baseline['headers'] or baseline['headers'][key] != value:
            changes['header_changes'].append(
                {'header': key, 'new_value': value, 'old_value': baseline['headers'].get(key)})
            changes_detected = True

    for key in baseline['headers']:
        if key not in current['headers']:
            changes['header_changes'].append({'header': key, 'new_value': None, 'old_value': baseline['headers'][key]})
            changes_detected = True

    return changes_detected, changes


def prompt_authorization(script_info):
    authorized_scripts = []
    for script in script_info:
        src = script['src']
        hash = script['hash']
        print(f"Script found: {src}")
        authorized = input("Authorize this script? (yes/no): ").strip().lower()
        if authorized == 'yes':
            justification = input("Provide justification for this script: ").strip()
            authorized_scripts.append({'src': src, 'hash': hash, 'justification': justification})
    return authorized_scripts


def generate_html_report(websites, changes_summary, details, baseline_data, csp_data):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def get_checkmark(is_passed):
        return "&#10004;" if is_passed else "&#10060;"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scan Report</title>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #FEFFE3;
                color: #333;
            }}
            .container {{
                max-width: 900px;
                margin: auto;
                background: #fff;
                padding: 20px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }}
            h1 {{
                font-size: 2em;
                color: #2c3e50;
                font-weight: bold;
                margin-bottom: 10px;
            }}
            h2 {{
                font-size: 1.5em;
                color: #2c3e50;
                margin-bottom: 10px;
            }}
            h3 {{
                font-size: 1.2em;
                color: #2c3e50;
                margin-bottom: 10px;
            }}
            p {{
                font-size: 1em;
                line-height: 1.5;
                color: #333;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
                table-layout: fixed;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 10px;
                text-align: left;
                overflow: hidden;
                text-overflow: ellipsis;
            }}
            th {{
                background-color: #A9BC22;
                color: white;
            }}
            .summary th, .details th, .authorized th {{
                background-color: #A9BC22;
                color: white;
            }}
            .new-script {{
                background-color: #d4edda;
            }}
            .changed-script {{
                background-color: #fff3cd;
            }}
            .removed-script {{
                background-color: #f8d7da;
            }}
            .header-change {{
                background-color: #ffcccc;
            }}
            .footer {{
                text-align: center;
                padding: 10px;
                background: #333;
                color: #fff;
                margin-top: 20px;
            }}
            .checkmark {{
                color: green;
                font-size: 1.2em;
            }}
            .compliance {{
                list-style-type: none;
                padding: 0;
                margin: 0 0 20px 0;
            }}
            .compliance li {{
                display: flex;
                align-items: center;
                margin-bottom: 10px;
            }}
            .compliance li span {{
                margin-left: 10px;
            }}
            .section {{
                margin-bottom: 20px;
                padding-bottom: 10px;
                border-bottom: 2px solid #A9BC22;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Scan Report</h1>
            <p><strong>Timestamp:</strong> {timestamp}</p>"""

    for url, changes in changes_summary.items():
        new_scripts_check = get_checkmark(len(changes.get('new_scripts', [])) == 0)
        changed_scripts_check = get_checkmark(len(changes.get('changed_scripts', [])) == 0)
        removed_scripts_check = get_checkmark(len(changes.get('removed_scripts', [])) == 0)
        html_content += f"""
            <div class="summary section">
                <h2>Summary of changes detected for {url} (compliance with PCI DSS 6.4.3 and 11.6.1):</h2>
                <ul class="compliance">
                    <li><span class="checkmark">{new_scripts_check}</span><span>Script is authorized.</span></li>
                    <li><span class="checkmark">{changed_scripts_check}</span><span>Script integrity is assured.</span></li>
                    <li><span class="checkmark">{removed_scripts_check}</span><span>Script inventory maintained.</span></li>
                </ul>
                <table>
                    <tr>
                        <th>Website</th>
                        <th>New Scripts</th>
                        <th>Changed Scripts</th>
                        <th>Removed Scripts</th>
                        <th>CSP Present</th>
                        <th>Header Changes</th>
                    </tr>
                    <tr>
                        <td>{url}</td>
                        <td>{len(changes.get('new_scripts', []))}</td>
                        <td>{len(changes.get('changed_scripts', []))}</td>
                        <td>{len(changes.get('removed_scripts', []))}</td>
                        <td>{"Yes" if csp_data[url] else "No"}</td>
                        <td>{"Yes" if changes.get('header_changes') else "No"}</td>
                    </tr>
                </table>
            </div>"""

    html_content += """
            <div class="details section">
                <h2>Detailed changes:</h2>"""

    for url, url_details in details.items():
        html_content += f"""
                <h3>Website: {url}</h3>
                <table>
                    <tr>
                        <th>Change Type</th>
                        <th>Script/Header</th>
                    </tr>"""
        if url_details.get('new_scripts'):
            for script in url_details['new_scripts']:
                html_content += f"""
                    <tr class="new-script">
                        <td>New script</td>
                        <td>{script}</td>
                    </tr>"""
        if url_details.get('changed_scripts'):
            for script in url_details['changed_scripts']:
                html_content += f"""
                    <tr class="changed-script">
                        <td>Changed script</td>
                        <td>{script}</td>
                    </tr>"""
        if url_details.get('removed_scripts'):
            for script in url_details['removed_scripts']:
                html_content += f"""
                    <tr class="removed-script">
                        <td>Removed script</td>
                        <td>{script}</td>
                    </tr>"""
        if url_details.get('header_changes'):
            for header_change in url_details['header_changes']:
                html_content += f"""
                    <tr class="header-change">
                        <td>Header change</td>
                        <td>Header: {header_change['header']}<br>Old Value: {header_change['old_value']}<br>New Value: {header_change['new_value']}</td>
                    </tr>"""
        html_content += """
                </table>"""

    html_content += """
            </div>
            <div class="authorized section">
                <h2>Authorized Scripts Inventory and Justification:</h2>"""

    for url, scripts in baseline_data.items():
        html_content += f"""
                <h3>Website: {url}</h3>
                <table>
                    <tr>
                        <th>Script</th>
                        <th>Hash</th>
                        <th>Justification</th>
                    </tr>"""
        for script in scripts['scripts']:
            html_content += f"""
                    <tr>
                        <td>{script['src']}</td>
                        <td>{script['hash']}</td>
                        <td>{script['justification']}</td>
                    </tr>"""
        html_content += """
                </table>"""

    html_content += """
        </div>
        <div class="footer">
            <p>Scan Report generated on {timestamp}</p>
        </div>
    </body>
    </html>"""

    with open(REPORT_FILE, 'w') as file:
        file.write(html_content)



def display_results(changes_summary, details, baseline_data, csp_data):
    print("\nSummary of changes detected (compliance with PCI DSS 6.4.3 and 11.6.1):")
    print("==============================================================\n")
    for url, changes in changes_summary.items():
        csp_present = "Yes" if csp_data[url] else "No"
        header_changes = "Yes" if changes.get('header_changes') else "No"
        print(f"Website: {url}")
        print(f"  New scripts: {len(changes.get('new_scripts', []))}")
        print(f"  Changed scripts: {len(changes.get('changed_scripts', []))}")
        print(f"  Removed scripts: {len(changes.get('removed_scripts', []))}")
        print(f"  CSP Present: {csp_present}")
        print(f"  Header Changes: {header_changes}")
        print("\n")

    print("Detailed changes:")
    print("==============================================================\n")
    for url, url_details in details.items():
        print(f"Website: {url}")
        for change_type, items in url_details.items():
            print(f"  {change_type.replace('_', ' ').capitalize()}:")
            for item in items:
                if change_type == 'header_changes':
                    print(f"    - Header: {item['header']}")
                    print(f"      Old Value: {item['old_value']}")
                    print(f"      New Value: {item['new_value']}")
                else:
                    print(f"    - {item}")
        print("\n")

    print("Authorized Scripts Inventory and Justification:")
    print("==============================================================\n")
    for url, scripts in baseline_data.items():
        print(f"Website: {url}")
        for script in scripts['scripts']:
            print(f"  Script: {script['src']}")
            print(f"  Hash: {script['hash']}")
            print(f"  Justification: {script['justification']}")
            print("\n")


def main():
    websites = []
    baseline_data = load_baseline()
    csp_data = {}

    while True:
        print("\nMenu:")
        print("1. Input list of websites")
        print("2. Perform baseline scan")
        print("3. Scan for changes")
        print("4. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            print("Enter the list of websites (comma-separated):")
            websites_input = input().strip()
            websites = [url.strip() for url in websites_input.split(',')]
        elif choice == '2':
            if not websites:
                print("No websites provided. Please input the list of websites first.")
                continue
            print("Performing baseline scan...")
            for url in websites:
                if not validate_url(url):
                    print(f"Invalid URL: {url}")
                    continue
                print(f"Checking {url}")
                current_scripts, headers = get_scripts_and_headers(url)
                csp_data[url] = has_csp(headers)
                print(f"Saving baseline for {url}")
                authorized_scripts = prompt_authorization(current_scripts)
                baseline_data[url] = {'scripts': authorized_scripts, 'headers': headers}
                save_baseline(baseline_data)
            print("Baseline scan completed.")
        elif choice == '3':
            if not websites:
                print("No websites provided. Please input the list of websites first.")
                continue
            if not baseline_data:
                print("No baseline found. Please perform a baseline scan first.")
                continue
            print("Scanning for changes...")
            changes_summary = {}
            details = {}
            for url in websites:
                if not validate_url(url):
                    print(f"Invalid URL: {url}")
                    continue
                print(f"Checking {url}")
                current_scripts, headers = get_scripts_and_headers(url)
                csp_data[url] = has_csp(headers)
                print(f"Comparing data for {url}")
                changes_detected, changes = compare_data(baseline_data[url],
                                                         {'scripts': current_scripts, 'headers': headers})
                changes_summary[url] = {
                    'new_scripts': changes.get('new_scripts', []),
                    'changed_scripts': changes.get('changed_scripts', []),
                    'removed_scripts': changes.get('removed_scripts', []),
                    'header_changes': changes.get('header_changes', [])
                }
                details[url] = changes if changes_detected else {}
                print(f"HTTP Headers for {url}:")
                for header, value in headers.items():
                    print(f"{header}: {value}")
            generate_html_report(websites, changes_summary, details, baseline_data, csp_data)
            display_results(changes_summary, details, baseline_data, csp_data)
            print("Scan for changes completed. HTML report generated.")
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == '__main__':
    main()
