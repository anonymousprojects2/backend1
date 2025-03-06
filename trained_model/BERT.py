import socket
import whois
import json
import subprocess
import requests
import time
import sys
import os
from datetime import datetime
from transformers import BertTokenizer, BertForSequenceClassification
from fpdf import FPDF
import torch

# Load the trained BERT model and tokenizer from the local directory using the nested path
print("Loading BERT tokenizer and model...")
start_time = time.time()
tokenizer = BertTokenizer.from_pretrained(r"C:\Users\mayan\OneDrive\Desktop\GG\PenTester\PenTester\trained_model\trained_model")
model = BertForSequenceClassification.from_pretrained(r"C:\Users\mayan\OneDrive\Desktop\GG\PenTester\PenTester\trained_model\trained_model")
model.eval()
print(f"Model and tokenizer loaded in {time.time() - start_time:.2f} seconds")

def get_ip(domain):
    """Get the IP address of a domain."""
    print(f"Resolving IP for domain: {domain}...")
    start_time = time.time()
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP resolved: {ip} in {time.time() - start_time:.2f} seconds")
        return ip
    except socket.gaierror as e:
        print(f"Failed to resolve IP for {domain}: {e}")
        return None

def get_whois(domain):
    """Fetch WHOIS information for a domain."""
    print(f"Fetching WHOIS information for domain: {domain}...")
    start_time = time.time()
    try:
        domain_info = whois.whois(domain)
        # Convert datetime objects to strings for JSON serialization
        def convert_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {k: convert_datetime(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_datetime(item) for item in obj]
            return obj
        result = json.dumps(convert_datetime(domain_info), indent=4)
        print(f"WHOIS information fetched in {time.time() - start_time:.2f} seconds")
        return result
    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")
        return f"WHOIS lookup failed: {e}"

def run_nmap_scan(ip):
    """Run an Nmap scan on the given IP."""
    if not ip:
        print("Nmap scan skipped: No valid IP address.")
        return "Nmap scan skipped: No valid IP address."
    print(f"Starting Nmap scan on IP: {ip}...")
    start_time = time.time()
    try:
        # Use -T4 for faster timing and -F for fewer ports (faster scan)
        result = subprocess.check_output(["nmap", "-T4", "-F", ip], stderr=subprocess.STDOUT, text=True, timeout=300)
        print(f"Nmap scan completed in {time.time() - start_time:.2f} seconds")
        return result
    except subprocess.TimeoutExpired:
        print("Nmap scan timed out after 300 seconds")
        return "Nmap scan timed out"
    except Exception as e:
        print(f"Nmap scan failed: {e}")
        return f"Nmap scan failed: {e}"

def test_sql_injection(target_url):
    """Perform an SQL Injection test using sqlmap with real-time output, enhanced debugging, and robust execution."""
    print(f"Starting SQL Injection test on URL: {target_url}...")
    start_time = time.time()
    sqlmap_path = r"C:\Users\mayan\OneDrive\Desktop\GG\PenTester\PenTester\sqlmap\sqlmap.py"
    
    # Verify if sqlmap.py exists with detailed debugging
    print(f"Checking for sqlmap.py at: {sqlmap_path}")
    if not os.path.exists(sqlmap_path) or not os.path.isfile(sqlmap_path):
        print(f"Error: sqlmap.py not found or is not a file at {sqlmap_path}. Path or file incorrect.")
        return "SQL Injection test skipped: sqlmap.py not found or invalid"
    print(f"sqlmap.py found. Checking permissions and readability...")
    if not os.access(sqlmap_path, os.R_OK):
        print(f"Error: Insufficient permissions to read {sqlmap_path}")
        return "SQL Injection test skipped: insufficient permissions for sqlmap.py"
    print(f"File permissions and existence verified.")
    print(f"Python interpreter: {sys.executable}")
    print(f"Working directory: {os.getcwd()}")

    try:
        # Check if sqlmap is available by running it with -h using Python, with significantly increased timeout
        print(f"Attempting to run: {sys.executable} {sqlmap_path} -h")
        process = subprocess.Popen([sys.executable, sqlmap_path, "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=os.path.dirname(sqlmap_path))
        stdout, stderr = process.communicate(timeout=1200)  # Increased timeout to 20 minutes (1200 seconds)
        print(f"sqlmap.py -h stdout: {stdout}")
        print(f"sqlmap.py -h stderr: {stderr}")
        if process.returncode != 0:
            raise FileNotFoundError(f"sqlmap failed with return code {process.returncode}: {stderr}")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"SQL Injection test skipped: sqlmap not found or not installed. Error: {e}")
        return "SQL Injection test skipped: sqlmap not found or not installed."

    try:
        # Run sqlmap with real-time output using Python, setting working directory
        print(f"Running SQL injection test with: {sys.executable} {sqlmap_path} -u {target_url} --batch --level=1 --risk=1 --smart --threads=10 --technique=B")
        process = subprocess.Popen([sys.executable, sqlmap_path, "-u", target_url, "--batch", "--level=1", "--risk=1", "--smart", "--threads=10", "--technique=B"], 
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, cwd=os.path.dirname(sqlmap_path))
        output = []
        while True:
            line = process.stdout.readline()
            if not line:
                break
            print(line.strip())  # Print each line of sqlmap output in real-time
            output.append(line)
        process.wait(timeout=1800)  # Increased timeout to 30 minutes (1800 seconds) for the full test
        result = "".join(output)
        print(f"SQL Injection test completed in {time.time() - start_time:.2f} seconds")
        return result
    except subprocess.TimeoutExpired:
        process.terminate()  # Terminate the process if it times out
        print("SQL Injection test timed out after 1800 seconds")
        return "SQL Injection test timed out"
    except Exception as e:
        print(f"SQL Injection test failed: {e}")
        return f"SQL Injection test failed: {e}"

def analyze_vulnerabilities(report_text):
    """Analyze vulnerabilities using the trained BERT model."""
    print(f"Analyzing vulnerabilities in report text (length: {len(report_text)} characters)...")
    start_time = time.time()
    inputs = tokenizer(report_text, return_tensors="pt", truncation=True, padding=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)
    predicted_label = torch.argmax(outputs.logits, dim=1).item()
    severity_map = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
    severity = severity_map.get(predicted_label, "Unknown")
    print(f"Vulnerability analysis completed in {time.time() - start_time:.2f} seconds with severity: {severity}")
    return severity

def generate_pdf_report(domain, ip, whois_data, results):
    """Generate a penetration testing report in PDF format."""
    print(f"Generating PDF report for domain: {domain}...")
    start_time = time.time()
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, "Penetration Testing Report", ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font("Arial", style='B', size=10)
    pdf.cell(40, 10, "Vulnerability Type", 1)
    pdf.cell(30, 10, "Severity", 1)
    pdf.cell(60, 10, "Affected Component", 1)
    pdf.cell(60, 10, "Description", 1)
    pdf.ln()
    pdf.set_font("Arial", size=10)
    
    for vuln_type, data in results.items():
        severity = analyze_vulnerabilities(data)
        pdf.cell(40, 10, vuln_type, 1)
        pdf.cell(30, 10, severity, 1)
        pdf.cell(60, 10, "Detected", 1)
        
        # Wrap text in PDF instead of truncating
        wrapped_text = "\n".join([data[i:i+50] for i in range(0, len(data), 50)])
        pdf.multi_cell(60, 10, wrapped_text, 1)
    
    pdf.output(f"{domain}_pentest_report.pdf")
    print(f"PDF report generated in {time.time() - start_time:.2f} seconds: {domain}_pentest_report.pdf")

def main():
    print("Starting penetration testing process...")
    domain = input("Enter domain name: ").strip()
    if not domain:
        print("Invalid domain.")
        return
    
    print(f"Processing domain: {domain}")
    ip = get_ip(domain)
    whois_data = get_whois(domain)
    
    results = {
        "WHOIS Information": whois_data,
        "Nmap Scan": run_nmap_scan(ip),
        "SQL Injection Test": test_sql_injection(f"http://{domain}")
    }
    
    generate_pdf_report(domain, ip, whois_data, results)
    print("Penetration testing process completed.")

if __name__ == "__main__":
    main()