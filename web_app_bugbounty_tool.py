"""
Web App Bug Bounty Helper (single-file)
Filename: web_app_bugbounty_tool.py

Overview:
A beginner-friendly, safe, and professional web app scanner focused on common checks:
- Security headers check
- robots.txt discovery
- Basic reflected XSS probe (non-destructive)
- Basic SQL injection probe (non-destructive, error-based checks)
- Simple directory discovery with a small built-in wordlist
- Optional Nmap service scan (if nmap is installed)
- Outputs: JSON report and a simple HTML report

Safety & Legal:
ONLY use this tool on web apps you own, have explicit permission to test (engagement/scope),
or intentionally vulnerable public test sites such as:
- OWASP Juice Shop (https://owasp.org/www-project-juice-shop/)
- DVWA (Damn Vulnerable Web App)
- testphp.vulnweb.com

Platform:
- Designed for Kali Linux (recommended). Also works on other Linux distros and Windows (with Python 3.10+ and required tools installed).

Dependencies:
pip install requests beautifulsoup4 jinja2 python-nmap
(If you don't want nmap features, python-nmap is optional.)

Quick usage examples:
python3 web_app_bugbounty_tool.py -u https://example.com
python3 web_app_bugbounty_tool.py -u http://127.0.0.1:8080 --nmap

Report files created:
- report_<host>_raw.json
- report_<host>.html

Notes on design choices:
- Non-destructive probes only: XSS payloads are test strings that are only checked for reflection; SQLi payloads are simple payloads looking for DB error patterns in responses.
- Uses reasonable timeouts and small concurrency to be friendly to targets.

Author: ChatGPT (prepared for your internship task)
"""

import argparse
import requests
import json
import os
import re
import time
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode
from bs4 import BeautifulSoup
from jinja2 import Template

# Optional nmap import
try:
    import nmap
    HAVE_NMAP = True
except Exception:
    HAVE_NMAP = False

# --- Config ---
REQUEST_TIMEOUT = 10
USER_AGENT = "BugBountyHelper/1.0 (+https://example.com)"
HEADERS = {"User-Agent": USER_AGENT}

DIR_WORDLIST = [
    'admin', 'login', 'dashboard', 'uploads', 'images', 'css', 'js', 'backup', 'config', 'test', 'api'
]

XSS_PAYLOADS = ["<script>alert('x')</script>", '" onmouseover="alert(1)"']
SQLI_PAYLOADS = ["' OR '1'='1", "' OR '1'='1' -- ", '" OR "" = "', ' or 1=1--']
SQL_ERROR_PATTERNS = [
    'mysql', 'syntax error', 'sql', 'unterminated quoted string', 'sqlstate', 'odbc', 'pdo', 'pg_fetch', 'syntax', 'mysql_fetch'
]

# --- Helper functions ---

def norm_url(u):
    if not u.startswith('http://') and not u.startswith('https://'):
        return 'http://' + u
    return u


def safe_get(url, **kwargs):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True, **kwargs)
        return resp
    except Exception as e:
        return None


# --- Checks ---

def check_security_headers(url):
    """Check for common security headers and return missing ones."""
    resp = safe_get(url)
    out = {'found': {}, 'missing': []}
    if not resp:
        out['error'] = 'No response'
        return out
    sec_headers = [
        'Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy'
    ]
    for h in sec_headers:
        if h in resp.headers:
            out['found'][h] = resp.headers.get(h)
        else:
            out['missing'].append(h)
    return out


def fetch_robots(url):
    parsed = urlparse(url)
    robots_url = parsed.scheme + '://' + parsed.netloc + '/robots.txt'
    resp = safe_get(robots_url)
    if not resp or resp.status_code != 200:
        return {'exist': False, 'content': None}
    return {'exist': True, 'content': resp.text}


def basic_directory_discovery(url, max_to_test=20):
    parsed = urlparse(url)
    base = parsed.scheme + '://' + parsed.netloc + '/'
    results = []
    count = 0
    for word in DIR_WORDLIST:
        if count >= max_to_test:
            break
        target = urljoin(base, word)
        resp = safe_get(target)
        if resp and resp.status_code < 400:
            results.append({'path': word, 'url': target, 'status': resp.status_code})
        count += 1
    return results


def find_forms_and_inputs(html_text):
    soup = BeautifulSoup(html_text, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        f = {}
        f['action'] = form.get('action')
        f['method'] = form.get('method', 'get').lower()
        inputs = []
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            i = {'name': input_tag.get('name'), 'type': input_tag.get('type')}
            inputs.append(i)
        f['inputs'] = inputs
        forms.append(f)
    return forms


def probe_xss(url):
    """Non-destructive reflected XSS probe: inject payloads into GET params and check for reflection."""
    resp = safe_get(url)
    if not resp:
        return {'error': 'No response'}
    findings = []
    # Parse query params
    parsed = urlparse(resp.url)
    params = dict(parse_qsl(parsed.query))
    # if no params, try forms
    if not params:
        # parse forms from HTML and test trivial injection on first text input if exists
        forms = find_forms_and_inputs(resp.text)
        for form in forms[:2]:
            # construct a naive form submit for GET forms only to be safe
            if form['method'] == 'get':
                action = form['action'] or parsed.path
                base = parsed.scheme + '://' + parsed.netloc
                full = urljoin(base, action)
                # build params
                p = {}
                for inp in form['inputs']:
                    if inp['name']:
                        p[inp['name']] = XSS_PAYLOADS[0]
                try:
                    r2 = requests.get(full, params=p, headers=HEADERS, timeout=REQUEST_TIMEOUT)
                    if r2 and XSS_PAYLOADS[0] in r2.text:
                        findings.append({'type': 'reflected-xss', 'vector': full, 'payload': XSS_PAYLOADS[0]})
                except Exception:
                    pass
        return {'findings': findings}

    # If there are params, test injection into each param
    for key in params.keys():
        for payload in XSS_PAYLOADS:
            tp = params.copy()
            tp[key] = payload
            try:
                r2 = requests.get(parsed.scheme + '://' + parsed.netloc + parsed.path, params=tp, headers=HEADERS, timeout=REQUEST_TIMEOUT)
                if r2 and payload in r2.text:
                    findings.append({'type': 'reflected-xss', 'param': key, 'payload': payload, 'url': r2.url})
            except Exception:
                continue
    return {'findings': findings}


def probe_sqli(url):
    """Non-destructive SQLi probe: inject payloads into GET params and look for error patterns."""
    resp = safe_get(url)
    if not resp:
        return {'error': 'No response'}
    findings = []
    parsed = urlparse(resp.url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        return {'findings': findings}
    for key in params.keys():
        for payload in SQLI_PAYLOADS:
            tp = params.copy()
            tp[key] = params[key] + payload
            try:
                r2 = requests.get(parsed.scheme + '://' + parsed.netloc + parsed.path, params=tp, headers=HEADERS, timeout=REQUEST_TIMEOUT)
                if not r2:
                    continue
                body = r2.text.lower()
                for pat in SQL_ERROR_PATTERNS:
                    if pat in body:
                        findings.append({'type': 'sqli-error', 'param': key, 'payload': payload, 'evidence': pat, 'url': r2.url})
                        break
            except Exception:
                continue
    return {'findings': findings}


def run_nmap_scan(target_host):
    if not HAVE_NMAP:
        return {'error': 'python-nmap not installed or nmap missing'}
    nm = nmap.PortScanner()
    try:
        scan = nm.scan(target_host, arguments='-sV -T4 --top-ports 100')
        return {'scan': scan}
    except Exception as e:
        return {'error': str(e)}


# --- Reporting ---

HTML_TEMPLATE = """
<html>
<head>
<meta charset="utf-8" />
<title>BugBountyHelper Report - {{host}}</title>
<style>
body{font-family: Arial, Helvetica, sans-serif; margin:20px}
.card{border:1px solid #ddd;padding:12px;margin-bottom:10px;border-radius:6px}
.h{font-size:18px;font-weight:700}
</style>
</head>
<body>
<h1>BugBountyHelper Report — {{host}}</h1>
<p>Generated at {{time}}</p>
{% for k,v in report.items() %}
<div class="card">
  <div class="h">{{k}}</div>
  <pre>{{ v | tojson(indent=2) }}</pre>
</div>
{% endfor %}
</body>
</html>
"""


def save_reports(host, report):
    safe_name = re.sub(r'[^A-Za-z0-9_.-]', '_', host)
    json_file = f"report_{safe_name}_raw.json"
    html_file = f"report_{safe_name}.html"
    with open(json_file, 'w') as f:
        json.dump(report, f, indent=2)
    tpl = Template(HTML_TEMPLATE)
    html = tpl.render(host=host, time=time.asctime(), report=report)
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html)
    return {'json': os.path.abspath(json_file), 'html': os.path.abspath(html_file)}


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(description='BugBountyHelper - simple web app scanner (non-destructive)')
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g. https://example.com)')
    parser.add_argument('--nmap', action='store_true', help='Run optional nmap service scan (requires nmap)')
    parser.add_argument('--max-dir', type=int, default=10, help='Max directory checks (default 10)')
    args = parser.parse_args()

    target = norm_url(args.url)
    parsed = urlparse(target)
    host = parsed.netloc

    print(f"Starting scan for {target}")
    report = {'target': target}

    print('Checking security headers...')
    report['security_headers'] = check_security_headers(target)

    print('Fetching robots.txt...')
    report['robots'] = fetch_robots(target)

    print('Directory discovery...')
    report['directories'] = basic_directory_discovery(target, max_to_test=args.max_dir)

    print('Probing for reflected XSS...')
    report['xss'] = probe_xss(target)

    print('Probing for SQL injection (error-based)...')
    report['sqli'] = probe_sqli(target)

    if args.nmap:
        print('Running nmap scan (optional)…')
        report['nmap'] = run_nmap_scan(host)

    print('Saving reports...')
    files = save_reports(host, report)
    print('Reports saved:')
    print(files)
    print('\nScan complete — remember to test only authorized targets.')


if __name__ == '__main__':
    main()
