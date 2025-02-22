import streamlit as st
import requests
import shodan
import whois
import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from dotenv import load_dotenv
import socket

# Load environment variables
load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API")

# Function to check SSL
def check_ssl(url):
    return "✅ Secure (SSL enabled)" if url.startswith("https://") else "❌ Not Secure (No SSL)"

# Function to check security headers
def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        return {
            "X-Frame-Options": headers.get("X-Frame-Options", "❌ Missing"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "❌ Missing"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "❌ Missing"),
        }
    except requests.exceptions.RequestException:
        return "⚠️ Unable to fetch headers (Invalid URL or server down)"


# resolve domain to IP address
def resolve_ip(domain):
    try:
        addr_info = socket.getaddrinfo(domain, None)
        ip_address = addr_info[0][4][0]  # Extract the first resolved IP
        return ip_address
    except socket.gaierror:
        return None


# Function to perform a Shodan scan
def shodan_scan(domain):

    if not SHODAN_API_KEY:
        return "⚠️ Shodan API Key is missing! Please check your environment variables."

    try:
        api = shodan.Shodan(SHODAN_API_KEY)

         # Resolve IP Address (Supports IPv4 & IPv6)
        ip_address = resolve_ip(domain)

        if not ip_address:
            return "⚠️ Failed to resolve domain to an IP address."

        # Query Shodan
        host = api.host(ip_address)
        
        return {
            "IP Address": host.get('ip_str', 'N/A'),
            "Open Ports": host.get('ports', []),
            "Vulnerabilities": host.get('vulns', []) or "No known vulnerabilities detected",
        }
    except shodan.APIError as e:
        return f"⚠️ Shodan API Error: {e}"
    except requests.exceptions.JSONDecodeError:
        return "⚠️ Shodan API Error: Unable to parse JSON response (Invalid response format)."
    except Exception as e:
        return f"⚠️ Unexpected error: {str(e)}"

# Function to perform WHOIS lookup
def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "Domain Name": w.domain_name,
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Owner": w.name or "Private",
        }
    except Exception:
        return "⚠️ WHOIS lookup failed (Domain might be private or incorrect)."

# Function to generate PDF report
def generate_pdf_report(url, ssl_status, headers_status, shodan_results, whois_results):
    c = canvas.Canvas("cybersecurity_report.pdf", pagesize=letter)
    width, height = letter

    c.setFont("Helvetica", 12)
    c.drawString(30, height - 30, "Cybersecurity Risk Report")
    c.drawString(30, height - 50, f"Website: {url}")

    c.drawString(30, height - 80, "🔍 SSL Certificate Check")
    c.drawString(30, height - 100, ssl_status)

    c.drawString(30, height - 130, "🔍 Security Headers Check")
    y = height - 150
    if isinstance(headers_status, dict):
        for header, value in headers_status.items():
            c.drawString(30, y, f"{header}: {value}")
            y -= 20
    else:
        c.drawString(30, y, headers_status)
        y -= 20

    c.drawString(30, y - 20, "🔍 Shodan Security Analysis")
    y -= 40
    if isinstance(shodan_results, dict):
        for key, value in shodan_results.items():
            c.drawString(30, y, f"{key}: {value}")
            y -= 20
    else:
        c.drawString(30, y, shodan_results)
        y -= 20

    c.drawString(30, y - 20, "🔍 WHOIS Lookup")
    y -= 40
    if isinstance(whois_results, dict):
        for key, value in whois_results.items():
            c.drawString(30, y, f"{key}: {value}")
            y -= 20
    else:
        c.drawString(30, y, whois_results)
        y -= 20

    c.save()

# UI
st.set_page_config(page_title="Cybersecurity Risk Checker", layout="wide")
# Styling for Dark Mode
st.markdown("""
    <style>
        body { background-color: #121212; color: white; }
        .stButton button { background-color: #007BFF; color: white; font-size: 18px; padding: 10px; border-radius: 10px; border: none; width: 100%; }
        .stTextInput input { font-size: 16px; padding: 8px; border-radius: 10px; }
        .stSubheader { color: #4DB6AC; }
    </style>
""", unsafe_allow_html=True)
st.title("🔒 Cybersecurity Risk Checker")
st.write("Analyze your website for vulnerabilities and security risks.")

url = st.text_input("Enter Website URL (e.g., https://example.com):", "")

if st.button("🔍 Run Security Check"):
    if url:
        st.success(f"Scanning {url} ...")
        
        # Perform checks
        ssl_status = check_ssl(url)
        headers_status = check_security_headers(url)
        domain = url.replace("https://", "").replace("http://", "")
        shodan_results = shodan_scan(domain)
        whois_results = get_whois_info(domain)

        # Display results
        st.subheader("🔍 SSL Certificate Check")
        st.write(ssl_status)

        st.subheader("🔍 Security Headers Check")
        if isinstance(headers_status, dict):
            for header, value in headers_status.items():
                st.write(f"**{header}:** {value}")
        else:
            st.write(headers_status)

        st.subheader("🔍 Shodan Security Analysis")
        if isinstance(shodan_results, dict):
            for key, value in shodan_results.items():
                st.write(f"**{key}:** {value}")
        else:
            st.write(shodan_results)

        st.subheader("🔍 WHOIS Lookup")
        if isinstance(whois_results, dict):
            for key, value in whois_results.items():
                st.write(f"**{key}:** {value}")
        else:
            st.write(whois_results)

        # Generate PDF Report
        generate_pdf_report(url, ssl_status, headers_status, shodan_results, whois_results)
        
        # Provide Download Link
        with open("cybersecurity_report.pdf", "rb") as file:
            st.download_button(label="📄 Download Security Report", data=file, file_name="cybersecurity_report.pdf", mime="application/pdf")

    else:
        st.error("Please enter a valid URL.")
