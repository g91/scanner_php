import os
import re
import sys

def search_vulnerabilities(directory):
    vulnerabilities = []
    file_pattern = re.compile(r'.*\.php$')
    rfi_pattern = re.compile(r'include(_once)?\s*\(\s*[\'"](http|https|ftp):\/\/')
    lfi_pattern = re.compile(r'include(_once)?\s*\(\s*[\$]?[\'"]\.\.[\\\/]')
    exec_pattern = re.compile(r'eval\s*\(\s*[\$]?[_A-Z0-9\s\[\]\'"]+\s*\)')

    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            if file_pattern.match(file):
                print(f"Checking file: {filepath}")

                with open(filepath, 'r') as f:
                    content = f.read()

                    if rfi_pattern.search(content):
                        vulnerabilities.append({
                            'file': filepath,
                            'vulnerability': 'RFI'
                        })

                    if lfi_pattern.search(content):
                        vulnerabilities.append({
                            'file': filepath,
                            'vulnerability': 'LFI'
                        })

                    if exec_pattern.search(content):
                        vulnerabilities.append({
                            'file': filepath,
                            'vulnerability': 'Code execution'
                        })

    return vulnerabilities


if len(sys.argv) < 2:
    print("Usage: python scanner_php.py directory_path")
    sys.exit(1)

directory_path = sys.argv[1]
if not os.path.isdir(directory_path):
    print("Invalid directory path.")
    sys.exit(1)

results = search_vulnerabilities(directory_path)

if results:
    print("\nVulnerabilities found:")
    for result in results:
        print(f"File: {result['file']}")
        print(f"Vulnerability: {result['vulnerability']}")
        print()
else:
    print("No vulnerabilities found.")
