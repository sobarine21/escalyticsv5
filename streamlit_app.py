import streamlit as st
import google.generativeai as genai
from langdetect import detect
from textblob import TextBlob
from fpdf import FPDF
from io import BytesIO
import concurrent.futures
import json
import docx2txt
from PyPDF2 import PdfReader
import re
import base64
from cryptography.fernet import Fernet
import email
from email import policy
from email.parser import BytesParser
from queue import Queue
import threading
import time
import asyncio
import aiohttp

# Configure API Key securely from Streamlit's secrets
genai.configure(api_key=st.secrets["GOOGLE_API_KEY"])

# Enterprise-Grade Security
# Generate encryption key (for demo purposes, generate new key every run)
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Streamlit App Configuration
st.set_page_config(page_title="Advanced Email AI", page_icon="📧", layout="wide")
st.title("📨 Advanced Email AI Analysis & Insights")
st.write("Extract insights, generate professional responses, and analyze emails with AI.")

# Default Enabled Features
features = {
    "sentiment": True,
    "highlights": True,
    "response": True,
    "export": True,
    "tone": True,
    "urgency": False,
    "task_extraction": True,
    "subject_recommendation": True,
    "category": False,
    "politeness": False,
    "emotion": False,
    "spam_check": False,
    "readability": False,
    "root_cause": False,
    "clarity": True,
    "best_response_time": False,
    "scenario_responses": True,  # Enable scenario-based suggested responses
    "attachment_analysis": True,  # Enable attachment analysis
    "complexity_reduction": True,  # Enable complexity reduction
    "phishing_detection": True,  # New Feature for Phishing Detection
    "sensitive_info_detection": True,  # New Feature for Sensitive Info Detection
    "confidentiality_rating": True,  # New Feature for Confidentiality Rating
    "attachment_summarization": True,  # New Feature for Attachment Content Extraction & Summarization
    "bias_detection": True,  # New Feature for Bias Detection
    "conflict_detection": True,  # New Feature for Conflict Detection in Email Threads
    "argument_mining": True,  # New Feature for Argument Mining
}

# Email Input Section
email_content = st.text_area("📩 Paste your email content here:", height=200)
MAX_EMAIL_LENGTH = 2000  # Increased for better analysis

# File Upload Section
uploaded_file = st.file_uploader("📎 Upload attachment for analysis (optional):", type=["txt", "pdf", "docx", "eml"])

# Scenario Dropdown Selection
scenario_options = [
    "Customer Complaint",
    "Product Inquiry",
    "Billing Issue",
    "Technical Support Request",
    "General Feedback",
    "Order Status",
    "Shipping Delay",
    "Refund Request",
    "Product Return",
    "Product Exchange",
    "Payment Issue",
    "Subscription Inquiry",
    "Account Recovery",
    "Account Update Request",
    "Cancellation Request",
    "Warranty Claim",
    "Product Defect Report",
    "Delivery Problem",
    "Product Availability",
    "Store Locator",
    "Service Appointment Request",
    "Installation Assistance",
    "Upgrade Request",
    "Compatibility Issue",
    "Product Feature Request",
    "Product Suggestions",
    "Customer Loyalty Inquiry",
    "Discount Inquiry",
    "Coupon Issue",
    "Service Level Agreement (SLA) Issue",
    "Invoice Clarification",
    "Tax Inquiry",
    "Refund Policy Inquiry",
    "Order Modification Request",
    "Credit Card Authorization Issue",
    "Security Inquiry",
    "Privacy Concern",
    "Product Manual Request",
    "Shipping Address Change",
    "Customer Support Availability Inquiry",
    "Live Chat Issue",
    "Email Support Response Inquiry",
    "Online Payment Gateway Issue",
    "E-commerce Website Bug Report",
    "Technical Documentation Request",
    "Mobile App Issue",
    "Software Update Request",
    "Product Recall Notification",
    "Urgent Request"
]

selected_scenario = st.selectbox("Select a scenario for suggested response:", scenario_options)

# Cache AI Responses for Performance
@st.cache_data(ttl=3600)
def get_ai_response(prompt, email_content):
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt + email_content[:MAX_EMAIL_LENGTH])
        return response.text.strip()
    except Exception as e:
        st.error(f"AI Error: {e}")
        return ""

# Additional Analysis Functions
def get_sentiment(email_content):
    return TextBlob(email_content).sentiment.polarity

def get_readability(email_content):
    return round(TextBlob(email_content).sentiment.subjectivity * 10, 2)  # Rough readability proxy

def export_pdf(text):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, text)
    return pdf.output(dest='S').encode('latin1')

def analyze_phishing_links(email_content):
    phishing_keywords = ["login", "verify", "update account", "account suspended", "urgent action required", "click here"]
    phishing_links = []
    urls = re.findall(r'(https?://\S+)', email_content)
    for url in urls:
        for keyword in phishing_keywords:
            if keyword.lower() in url.lower():
                phishing_links.append(url)
    return phishing_links

def detect_sensitive_information(email_content):
    # Regular expressions to detect sensitive information (phone numbers, email addresses, credit card numbers, etc.)
    sensitive_info_patterns = {
        "phone_number": r"(\+?\d{1,2}\s?)?(\(?\d{3}\)?|\d{3})[\s\-]?\d{3}[\s\-]?\d{4}",
        "email_address": r"[\w\.-]+@[\w\.-]+\.\w+",
        "credit_card": r"\b(?:\d[ -]*?){13,16}\b"
    }
    
    sensitive_data = {}
    for key, pattern in sensitive_info_patterns.items():
        matches = re.findall(pattern, email_content)
        if matches:
            sensitive_data[key] = matches
    return sensitive_data

def confidentiality_rating(email_content):
    # A simple approach to rating confidentiality based on the presence of certain keywords
    keywords = ["confidential", "private", "restricted", "not for distribution"]
    rating = sum(1 for keyword in keywords if keyword.lower() in email_content.lower())
    return min(rating, 5)  # Rating out of 5

# Analyze attachment based on its type
def analyze_attachment(file):
    try:
        if file.type == "text/plain":
            return file.getvalue().decode("utf-8")
        elif file.type == "application/pdf":
            reader = PdfReader(file)
            text = ""
            for page in reader.pages:
                text += page.extract_text()
            return text
        elif file.type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
            return docx2txt.process(file)
        elif file.type == "message/rfc822":
            msg = BytesParser(policy=policy.default).parsebytes(file.getvalue())
            return msg.get_body(preferencelist=('plain')).get_content()
        else:
            return "Unsupported file type."
    except Exception as e:
        return f"Error analyzing attachment: {e}"

# Asynchronous AI Response Fetching
async def async_get_ai_response(prompt, email_content):
    async with aiohttp.ClientSession() as session:
        try:
            model = genai.GenerativeModel("gemini-1.5-flash", session=session)
            response = await model.generate_content(prompt + email_content[:MAX_EMAIL_LENGTH])
            return response.text.strip()
        except Exception as e:
            return f"AI Error: {e}"

# Asynchronous Email Processing
async def process_email_async(email_content, uploaded_file, selected_scenario):
    detected_lang = detect(email_content)
    if detected_lang != "en":
        st.error("⚠️ Only English language is supported.")
    else:
        with st.spinner("⚡ Processing email insights..."):
            tasks = []
            if features["highlights"]:
                tasks.append(async_get_ai_response("Summarize this email concisely:\n\n", email_content))
            if features["response"]:
                tasks.append(async_get_ai_response("Generate a professional response to this email:\n\n", email_content))
            if features["tone"]:
                tasks.append(async_get_ai_response("Detect the tone of this email:\n\n", email_content))
            if features["task_extraction"]:
                tasks.append(async_get_ai_response("List actionable tasks:\n\n", email_content))
            if features["subject_recommendation"]:
                tasks.append(async_get_ai_response("Suggest a professional subject line:\n\n", email_content))
            if features["clarity"]:
                tasks.append(async_get_ai_response("Rate the clarity of this email:\n\n", email_content))
            if features["complexity_reduction"]:
                tasks.append(async_get_ai_response("Explain this email in the simplest way possible:\n\n", email_content))
            if features["scenario_responses"]:
                scenario_prompt = f"Generate a response for a {selected_scenario.lower()}:\n\n"
                tasks.append(async_get_ai_response(scenario_prompt, email_content))
            if uploaded_file and features["attachment_analysis"]:
                attachment_text = analyze_attachment(uploaded_file)
                tasks.append(async_get_ai_response("Analyze this attachment content:\n\n", attachment_text))
            if uploaded_file and features["attachment_summarization"]:
                attachment_text = analyze_attachment(uploaded_file)
                tasks.append(async_get_ai_response("Summarize this attachment content:\n\n", attachment_text))
            if features["bias_detection"]:
                tasks.append(async_get_ai_response("Identify potential biases in this email:\n\n", email_content))
            if features["conflict_detection"]:
                tasks.append(async_get_ai_response("Detect conflicts in this email thread:\n\n", email_content))
            if features["argument_mining"]:
                tasks.append(async_get_ai_response("Analyze the arguments presented in this email:\n\n", email_content))

            results = await asyncio.gather(*tasks)

            # Display Results Based on Enabled Features
            if features["highlights"]:
                st.subheader("📌 Email Summary")
                st.write(results.pop(0))
            if features["response"]:
                st.subheader("✉️ Suggested Response")
                st.write(results.pop(0))
            if features["tone"]:
                st.subheader("🎭 Email Tone")
                st.write(results.pop(0))
            if features["task_extraction"]:
                st.subheader("📝 Actionable Tasks")
                st.write(results.pop(0))
            if features["subject_recommendation"]:
                st.subheader("📬 Subject Line Recommendation")
                st.write(results.pop(0))
            if features["clarity"]:
                st.subheader("🔍 Email Clarity Score")
                st.write(results.pop(0))
            if features["complexity_reduction"]:
                st.subheader("🔽 Simplified Explanation")
                st.write(results.pop(0))
            if features["scenario_responses"]:
                st.subheader("📜 Scenario-Based Suggested Response")
                st.write(f"**{selected_scenario}:**")
                st.write(results.pop(0))
            if uploaded_file and features["attachment_analysis"]:
                st.subheader("📎 Attachment Analysis")
                st.write(results.pop(0))
            if uploaded_file and features["attachment_summarization"]:
                st.subheader("📎 Attachment Summary")
                st.write(results.pop(0))
            if features["bias_detection"]:
                st.subheader("⚖️ Bias Detection")
                st.write(results.pop(0))
            if features["conflict_detection"]:
                st.subheader("🚨 Conflict Detection")
                st.write(results.pop(0))
            if features["argument_mining"]:
                st.subheader("💬 Argument Mining")
                st.write(results.pop(0))

            # Phishing Links
            phishing_links = analyze_phishing_links(email_content) if features["phishing_detection"] else []
            if phishing_links:
                st.subheader("⚠️ Phishing Links Detected")
                st.write(phishing_links)

            # Sensitive Information Detected
            sensitive_info = detect_sensitive_information(email_content) if features["sensitive_info_detection"] else {}
            if sensitive_info:
                st.subheader("⚠️ Sensitive Information Detected")
                st.json(sensitive_info)

            # Confidentiality Rating
            confidentiality = confidentiality_rating(email_content) if features["confidentiality_rating"] else 0
            if confidentiality:
                st.subheader("🔐 Confidentiality Rating")
                st.write(f"Confidentiality Rating: {confidentiality}/5")

            # Export Options
            if features["export"]:
                export_data = {
                    "summary": results[0] if features["highlights"] else None,
                    "response": results[1] if features["response"] else None,
                    "tone": results[2] if features["tone"] else None,
                    "tasks": results[3] if features["task_extraction"] else None,
                    "subject_recommendation": results[4] if features["subject_recommendation"] else None,
                    "clarity_score": results[5] if features["clarity"] else None,
                    "complexity_reduction": results[6] if features["complexity_reduction"] else None,
                    "scenario_response": results[7] if features["scenario_responses"] else None,
                    "attachment_analysis": results[8] if features["attachment_analysis"] else None,
                    "attachment_summarization": results[9] if features["attachment_summarization"] else None,
                    "phishing_links": phishing_links,
                    "sensitive_info": sensitive_info,
                    "confidentiality": confidentiality,
                    "bias_detection": results[10] if features["bias_detection"] else None,
                    "conflict_detection": results[11] if features["conflict_detection"] else None,
                    "argument_mining": results[12] if features["argument_mining"] else None,
                }
                export_json = json.dumps(export_data, indent=4)
                st.download_button("📥 Download JSON", data=export_json, file_name="analysis.json", mime="application/json")

                pdf_data = export_pdf(json.dumps(export_data, indent=4))
                st.download_button("📥 Download PDF", data=pdf_data, file_name="analysis.pdf", mime="application/pdf")

# Start processing queue in a separate thread
def process_queue():
    while True:
        if not request_queue.empty():
            email_content, uploaded_file, scenario = request_queue.get()
            asyncio.run(process_email_async(email_content, uploaded_file, scenario))
            request_queue.task_done()
        time.sleep(1)

threading.Thread(target=process_queue, daemon=True).start()

# Add request to queue when button clicked
if (email_content or uploaded_file) and st.button("🔍 Generate Insights"):
    request_queue.put((email_content, uploaded_file, selected_scenario))
    queue_size = request_queue.qsize()
    if queue_size > 1:
        eta = (queue_size - 1) * processing_time_per_request
        st.info(f"⏳ Your request is in the queue. Estimated wait time: {eta} seconds.")
    else:
        st.info("⚡ Your request is being processed.")
else:
    st.info("✏️ Paste email content and click 'Generate Insights' to begin.")
