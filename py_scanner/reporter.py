# This file is responsible for generating the HTML report of the scan findings.

from pathlib import Path # For working with file paths easily
from typing import List, Dict, Any # For type hinting, making our code clearer
from jinja2 import Template # Our templating engine to generate dynamic HTML

# We're embedding the entire HTML template directly into this Python file.
# Why? Well, it makes our scanner super portable! You can just share this one Python file,
# and it'll work everywhere without needing separate template files.
# It also prevents annoying "template not found" errors if someone runs the script
# from an unexpected directory. It's a trade-off for simplicity and portability.
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            background-color: #f4f4f9; 
            color: #333; 
            margin: 0; 
            padding: 20px; 
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 40px; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        h1 { 
            border-bottom: 2px solid #eee; 
            padding-bottom: 20px; 
            margin-bottom: 30px; 
            color: #2c3e50; 
        }
        .summary { 
            display: flex; 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .card { 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 6px; 
            flex: 1; 
            text-align: center; 
            border: 1px solid #e9ecef; 
        }
        .card h2 { 
            margin: 0; 
            font-size: 2em; 
            color: #2c3e50; 
        }
        .card p { 
            margin: 5px 0 0; 
            color: #6c757d; 
            font-weight: 500; 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px; 
        }
        th, td { 
            padding: 12px 15px; 
            text-align: left; 
            border-bottom: 1px solid #e1e4e8; 
        }
        th { 
            background-color: #f8f9fa; 
            font-weight: 600; 
            color: #444; 
        }
        tr:hover { 
            background-color: #f8f9fa; 
        }
        .type-badge { 
            display: inline-block; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-size: 0.85em; 
            font-weight: 600; 
        }
        .type-secret { 
            background: #ffebee; 
            color: #c62828; 
        }
        .type-pii { 
            background: #e3f2fd; 
            color: #1565c0; 
        }
        .type-api { 
            background: #fff3e0; 
            color: #ef6c00; 
        }
        .type-ai { 
            background: #f3e5f5; 
            color: #7b1fa2; 
        }
        .code-snippet { 
            font-family: 'Courier New', monospace; 
            background: #f1f1f1; 
            padding: 2px 5px; 
            border-radius: 3px; 
            word-break: break-all; 
        }
        .footer { 
            margin-top: 40px; 
            text-align: center; 
            color: #999; 
            font-size: 0.9em; 
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Scan Report: {{ domain }}</h1>
        
        <div class="summary">
            <div class="card">
                <h2>{{ total_findings }}</h2>
                <p>Total Findings</p>
            </div>
            <div class="card">
                <h2>{{ unique_files }}</h2>
                <p>Files Affected</p>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th style="width: 20%">Type</th>
                    <th style="width: 40%">Details</th>
                    <th style="width: 35%">Location</th>
                    <th style="width: 5%">Line</th>
                </tr>
            </thead>
            <tbody>
                {% for finding in findings %}
                <tr>
                    <td>
                        {% if 'Secret' in finding.type or 'Key' in finding.type %}
                            <span class="type-badge type-secret">{{ finding.type }}</span>
                        {% elif 'PII' in finding.type %}
                            <span class="type-badge type-pii">{{ finding.type }}</span>
                        {% elif 'LLM' in finding.type %}
                            <span class="type-badge type-ai">{{ finding.type }}</span>
                        {% else %}
                            <span class="type-badge type-api">{{ finding.type }}</span>
                        {% endif %}
                    </td>
                    <td>
                        <div class="code-snippet">{{ finding.details }}</div>
                    </td>
                    <td><a href="{{ finding.file_url }}" target="_blank">{{ finding.file_url }}</a></td>
                    <td>{{ finding.line }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <div class="footer">
            Generated by AST-based Client-Side Scanner
        </div>
    </div>
</body>
</html>
"""

def generate_html_report(findings: List[Dict[str, Any]], domain: str, output_path: Path):
    """
    This function takes all the scan findings and generates a beautiful,
    standalone HTML report file. We use Jinja2 for templating because
    trying to build complex HTML with f-strings can get really messy!
    """
    # If there are no findings, there's nothing to report, so we just stop here.
    if not findings:
        print("[INFO] No findings to report. Skipping HTML report generation.")
        return

    # Let's figure out how many unique files have issues.
    # We create a set of file URLs to automatically count only unique ones.
    unique_files = len(set(f['file_url'] for f in findings))
    
    # Now, we load our embedded HTML template.
    template = Template(HTML_TEMPLATE)
    
    # We render the template, passing in all the data it needs to fill out the report.
    html_content = template.render(
        domain=domain, # The domain or project name for the report title
        findings=findings, # The list of all individual findings
        total_findings=len(findings), # The total count of all findings
        unique_files=unique_files # The number of distinct files affected
    )

    # Time to save our shiny new HTML report to a file!
    try:
        # We open the specified output path in write mode ('w'), ensuring UTF-8 encoding
        # for broad compatibility with different characters.
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content) # Write the generated HTML content to the file
        print(f"[SUCCESS] HTML Report successfully generated at: {output_path}")
    except Exception as e:
        # Oh no, something went wrong while trying to write the file.
        # We'll print an error message to let the user know.
        print(f"[ERROR] Could not generate HTML report. An error occurred: {e}")