import streamlit as st
import pandas as pd
import random
import time
import base64

# --- Configuration ---
OFFICIAL_HANDLE = "Odisha_Police"
OFFICIAL_NAME = "Odisha Police"
RISK_THRESHOLD_HIGH = 70
RISK_THRESHOLD_MEDIUM = 40

# --- Helper Functions ---

def get_similarity_score(suspect_handle, official_handle):
    """
    Calculates a score based on handle similarity.
    Max score of 1.0 (100% match) for perfect handle match.
    Specific logic to detect common typos like '0' (zero) for 'O' (letter).
    """
    suspect_lower = suspect_handle.lower().strip()
    official_lower = official_handle.lower().strip()

    if suspect_lower == official_lower:
        return 1.0
    
    # Critical typo: '0' (zero) substituted for 'o' (letter)
    if suspect_lower.replace('0', 'o', 1) == official_lower and '0' in suspect_lower:
         return 0.99
    
    # Generic single-character difference check
    if len(suspect_handle) == len(official_handle) and sum(a != b for a, b in zip(suspect_lower, official_lower)) == 1:
        return 0.90
        
    return 0.20


def keyword_scan_score(post_content):
    """Mocks scanning post content for high-risk fraud keywords (Behavioral Module)."""
    # Expanded list of fraud keywords
    fraud_keywords = ["otp", "wallet", "send money", "urgent funds", "transfer now", "fine", "penalty", "account frozen", "kyc update", "click link", "tax refund", "jail"]
    risk = 0
    
    # Specific high-risk phrase detection
    if "urgent" in post_content.lower() and ("money" in post_content.lower() or "fund" in post_content.lower()):
        risk += 25  
    
    # Generic keyword detection
    for keyword in fraud_keywords:
        if keyword in post_content.lower():
            risk += 15
            
    return min(risk, 60) # Max raw risk contribution from generic behavior is 60

def calculate_risk_score(handle, recent_posts, is_established_account, domain_age_risk, profile_pic_stolen, urgency_tone_risk, phishing_link_risk):
    """
    Calculates the overall Impersonation Risk Score (Max 100) by aggregating scores from all modules.
    """
    
    identity_risk = 0  # Max 45 points
    behavior_risk = 0  # Max 40 points
    network_risk = 0   # Max 15 points
    
    # 1. Identity Module (Max 45 points)
    identity_score = get_similarity_score(handle, OFFICIAL_HANDLE)
    
    if identity_score == 1.0:
        identity_risk = 0
    elif identity_score == 0.99:
        # Near perfect match (typo like 0 for O) is highest risk from identity
        identity_risk = 43 + random.randint(0, 2) # 43-45
    elif identity_score == 0.90:
        # Single character difference
        identity_risk = 25 + random.randint(0, 5) # 25-30
    else:
        identity_risk = 5 + random.randint(0, 5) # Low identity risk
    
    # Confidence Score Calculation (Mock)
    if identity_score == 1.0 or identity_score <= 0.20:
        # High confidence in low/perfect identity match
        confidence_score = random.uniform(90.0, 99.9)
    elif identity_score >= 0.90:
        # Lower confidence when dealing with subtle typos
        confidence_score = random.uniform(70.0, 89.9)
    else:
        confidence_score = random.uniform(50.0, 69.9) 


    # 2. Behavioral Module (Max 40 points)
    behavior_risk_raw = keyword_scan_score(recent_posts)
    
    # Feature 1: Urgency Tone (Max 15 points) - NEW
    urgency_points = 0
    if urgency_tone_risk == "High Urgency (Threat/Panic)":
        urgency_points = 15
    elif urgency_tone_risk == "Medium Urgency (Time Pressure)":
        urgency_points = 7
        
    # Scale generic keyword score (max 60) to max 25 points, leaving 15 points for Urgency Tone
    keyword_points = int(behavior_risk_raw * (25 / 60))

    behavior_risk = keyword_points + urgency_points
    behavior_risk = min(behavior_risk, 40)
    
    # 3. Network/Metadata Score (Max 15 points)
    
    account_age_days = random.randint(300, 500)
    if not is_established_account:
        # 5 points for new account (max 5/15)
        network_risk += 5 + random.randint(0, 2)
        account_age_days = random.randint(1, 90)
        
    # Network Feature 1a: External Link Domain Age Check (Max 3 points)
    domain_age_points = 0
    if domain_age_risk == "High Risk (New/Suspicious Domain)":
        domain_age_points = 3 
    elif domain_age_risk == "Medium Risk (Recently Updated Domain)":
        domain_age_points = 1
    
    # Network Feature 1b: Phishing Link/Homoglyph Check (Max 3 points) - NEW FEATURE
    phishing_points = 0
    if phishing_link_risk == "Homoglyph/Typosquatting Detected":
        phishing_points = 3
    elif phishing_link_risk == "Malicious Domain Structure Detected":
        phishing_points = 1
    
    # Network Feature 2: Stolen Profile Picture Check (Max 4 points)
    stolen_pic_points = 0
    if profile_pic_stolen == "Yes (Stolen/Official Image Match)":
        stolen_pic_points = 4
    
    network_risk += domain_age_points + phishing_points + stolen_pic_points
    # Ensure network risk maxes out at 15
    network_risk = min(network_risk, 15)
    
    final_score_raw = identity_risk + behavior_risk + network_risk 
    
    # Add a small random jitter and cap the score
    final_score = min(final_score_raw + random.randint(-5, 5), 100)
    final_score = max(final_score, 0)
    
    return final_score, {
        "Handle Similarity Score (%)": round(identity_score * 100, 2),
        "Identity Risk Points (Max 45)": identity_risk,
        "Keyword Scan Points (Max 25)": keyword_points,
        "Urgency Tone Points (Max 15)": urgency_points, # NEW
        "Behavioral Risk Points (Max 40)": behavior_risk,
        "Network/Metadata Risk Points (Max 15)": network_risk,
        "Account Age (Days)": account_age_days,
        "Domain Age Risk Points": domain_age_points,
        "Phishing Link Points": phishing_points, # NEW
        "Stolen Picture Risk Points": stolen_pic_points,
        "Confidence Score (%)": round(confidence_score, 2) 
    }

# --- Dynamic Action Suggestion Logic ---
def get_action_suggestion(risk_score):
    """Provides specific next steps and corresponding Streamlit style based on the risk score."""
    if risk_score >= RISK_THRESHOLD_HIGH:
        return (
            "🚨 *IMMEDIATE TAKEDOWN & FORENSIC TRACE:* Initiate platform-specific emergency takedown protocol. Begin forensic tracing of associated wallet addresses and IP logs.", 
            "error", # Corresponds to st.error
            'HIGH RISK: IMMEDIATE TAKEDOWN REQUIRED'
        )
    elif risk_score >= RISK_THRESHOLD_MEDIUM:
        return (
            "⚠ *MANDATORY MANUAL REVIEW & MONITORING:* Escalate to a Level 2 Analyst for mandatory human review. Set up automated monitoring for further post activity over the next 48 hours.",
            "warning", # Corresponds to st.warning
            'MEDIUM RISK: INVESTIGATE URGENTLY'
        )
    else:
        return (
            "✅ *SCHEDULED RE-EVALUATION:* No immediate action required. Profile will be marked for re-evaluation in 7 days to check for any changes in risk factors or behavioral patterns.",
            "info", # Corresponds to st.info
            'LOW RISK: MONITOR'
        )

# --- HTML Generator Function (For PDF Report Download) ---
def create_html_report(final_score, breakdown, suspect_url, suspect_handle, suspect_posts, suggestion_text, risk_label):
    """Generates a styled HTML string for the downloadable forensic report."""
    
    # Determine Risk Color for the report
    if final_score >= RISK_THRESHOLD_HIGH:
        risk_color = '#CC0000' # Red
    elif final_score >= RISK_THRESHOLD_MEDIUM:
        risk_color = '#FFCC00' # Yellow/Amber
    else:
        risk_color = '#008000' # Green
    
    confidence = breakdown.get("Confidence Score (%)", "N/A")
    
    # Construct the HTML content using professional styling
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Hawk-Eye AI Forensic Report</title>
        <style>
            /* Professional, clean CSS structure for printing */
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; line-height: 1.6; }}
            .container {{ width: 850px; margin: 0 auto; border: 1px solid #ccc; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            
            /* Header */
            .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; margin-bottom: 20px; border-radius: 5px; }}
            .header h1 {{ margin: 0; font-size: 26px; }}
            .header p {{ margin: 5px 0 0; font-size: 14px; opacity: 0.9; }}
            
            /* Section Styling */
            h2 {{ border-bottom: 2px solid #3498db; padding-bottom: 5px; margin-top: 25px; color: #34495e; font-size: 20px; }}
            
            /* Risk Summary Box */
            .risk-summary-box {{ 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                padding: 15px 20px; 
                margin-bottom: 20px; 
                border-radius: 8px; 
                border: 2px solid {risk_color};
                background-color: #f4f6f7;
            }}
            .risk-score {{ font-size: 36px; font-weight: bold; color: {risk_color}; }}
            .risk-label {{ font-size: 20px; font-weight: bold; color: #333; }}
            
            /* Table Styling */
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; font-size: 14px; }}
            th {{ background-color: #ecf0f1; color: #34495e; }}
            .value-column {{ font-weight: bold; width: 30%; }}

            /* Action Suggestion Box */
            .action-suggestion {{
                background-color: #fcf8e3;
                border: 1px solid #f9d863;
                color: #8a6d3b;
                padding: 15px;
                margin-top: 15px;
                border-radius: 5px;
            }}

            /* Post Content Block */
            .post-content {{ 
                background-color: #ecf0f1; 
                border-left: 5px solid #3498db; 
                padding: 15px; 
                margin-top: 10px;
                white-space: pre-wrap;
                font-style: italic;
            }}

            /* Footer */
            .footer {{ text-align: center; margin-top: 40px; font-size: 12px; color: #7f8c8d; }}

            /* Specific styling for the risk label color */
            .risk-value {{ color: {risk_color}; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🚨 HAWK-EYE AI FORENSIC REPORT</h1>
                <p>Instant Deception Detector | Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>

            <h2>1. Final Impersonation Risk Summary</h2>
            <div class="risk-summary-box">
                <div>
                    <div class="risk-label">Risk Level:</div>
                    <div class="risk-score risk-value">{risk_label}</div>
                </div>
                <div style="text-align: right;">
                    <div class="risk-label">Calculated Risk Score:</div>
                    <div class="risk-score risk-value">{final_score}%</div>
                </div>
            </div>
            
            <div class="action-suggestion">
                <strong>Action Suggestion:</strong> {suggestion_text}
            </div>

            <h2>2. Suspect Profile & Reference</h2>
            <table>
                <tr>
                    <th>Field</th>
                    <th class="value-column">Value</th>
                </tr>
                <tr>
                    <td>*Suspect URL*</td>
                    <td class="value-column"><a href="{suspect_url}" target="_blank">{suspect_url}</a></td>
                </tr>
                <tr>
                    <td>*Suspect Handle*</td>
                    <td class="value-column">{suspect_handle}</td>
                </tr>
                <tr>
                    <td>*Official Handle Reference*</td>
                    <td class="value-column">{OFFICIAL_HANDLE}</td>
                </tr>
            </table>

            <h2>3. Detailed Risk Breakdown (Max 100 Points)</h2>
            <table>
                <tr>
                    <th>Risk Factor</th>
                    <th>Score Detail</th>
                    <th class="value-column">Points Earned</th>
                </tr>
                <tr>
                    <td>*Identity Risk (Max 45)*</td>
                    <td>Handle Similarity: {breakdown.get("Handle Similarity Score (%)")}%</td>
                    <td class="value-column">{breakdown.get("Identity Risk Points (Max 45)")}</td>
                </tr>
                <tr>
                    <td>*Behavioral Risk (Max 40)*</td>
                    <td>
                        Keyword Scan Points: {breakdown.get("Keyword Scan Points (Max 25)")}<br>
                        *Urgency Tone Points (NEW)*: {breakdown.get("Urgency Tone Points (Max 15)")}
                    </td>
                    <td class="value-column">{breakdown.get("Behavioral Risk Points (Max 40)")}</td>
                </tr>
                <tr>
                    <td>*Network/Metadata Risk (Max 15)*</td>
                    <td>
                        Account Age: {breakdown.get("Account Age (Days)")} days<br>
                        Domain Age Risk Points: {breakdown.get("Domain Age Risk Points")}<br>
                        *Phishing Link Points (NEW)*: {breakdown.get("Phishing Link Points")}<br>
                        Stolen Pic Risk Points: {breakdown.get("Stolen Picture Risk Points")}
                    </td>
                    <td class="value-column">{breakdown.get("Network/Metadata Risk Points (Max 15)")}</td>
                </tr>
                <tr>
                    <td style="background-color: #dbe4f1; font-weight: bold;">*AI Confidence Score*</td>
                    <td style="background-color: #dbe4f1;">Model's certainty in the calculated risk.</td>
                    <td class="value-column" style="background-color: #dbe4f1;">{confidence}%</td>
                </tr>
                <tr style="background-color: #e5e7e9; font-weight: bold;">
                    <td>*TOTAL RISK SCORE*</td>
                    <td></td>
                    <td class="value-column">{final_score} / 100</td>
                </tr>
            </table>

            <h2>4. Evidential Content</h2>
            <p><strong>Recent Post Content Scanned:</strong></p>
            <div class="post-content">
                {suspect_posts}
            </div>

            <div class="footer">
                This document is a machine-generated forensic snapshot and is intended for official use only.
            </div>
        </div>
    </body>
    </html>
    """
    return html_content

# --- Streamlit UI ---

st.set_page_config(layout="wide", page_title="Hawk-Eye AI: Instant Deception Detector")

# Custom CSS for the dashboard look and feel (Dark Theme)
st.markdown("""
<style>
.stApp {
    background-color: #0d1117;
    color: #c9d1d9;
}
h1, h2, h3, .stButton>button {
    color: #58a6ff;
}

/* FIX: This targets all main widget labels (text inputs, text areas, select boxes) */
.stApp label {
    color: #c9d1d9 !important; /* Light gray color for visibility on dark background */
    font-weight: 500;
}

/* NEW FIX: Specifically targeting the text of radio button options to ensure white color */
div[data-testid*="stRadio"] label p {
    color: white !important;
}

.stMetric {
    background-color: #161b22;
    padding: 15px;
    border-radius: 10px;
    border: 1px solid #30363d;
}
/* Style for colored risk badges */
.risk-high {
    background-color: #6d0a0a;
    color: white;
    padding: 10px;
    border-radius: 5px;
    font-weight: bold;
    text-align: center;
}
.risk-medium {
    background-color: #d1b10a;
    color: black;
    padding: 10px;
    border-radius: 5px;
    font-weight: bold;
    text-align: center;
}
.risk-low {
    background-color: #1f643f;
    color: white;
    padding: 10px;
    border-radius: 5px;
    font-weight: bold;
    text-align: center;
}
.header-box {
    background-color: #161b22;
    padding: 20px;
    border-radius: 10px;
    border-bottom: 3px solid #58a6ff;
    margin-bottom: 20px;
}
</style>
""", unsafe_allow_html=True)

# Application Header
st.markdown('<div class="header-box"><h1>🚨 Hawk-Eye AI: Impersonation Detector</h1><h3>Instant Deception Detector</h3></div>', unsafe_allow_html=True)

# Input Section
with st.container():
    st.header("Suspect Profile Input")
    col1, col2 = st.columns([3, 1])

    with col1:
        suspect_url = st.text_input(
            "Enter Suspect Social Media URL",
            placeholder=f"e.g., https://twitter.com/0disha_Police",
            key="url_input"
        )
        suspect_handle = st.text_input(
            "Mock Suspect Handle", 
            placeholder="e.g., 0disha_Police (Using zero '0' instead of letter 'O')",
            key="handle_input_v3"
        )
        
    with col2:
        st.markdown("---")
        st.write(f"*Official Reference:*")
        st.code(f"Handle: {OFFICIAL_HANDLE}", language='text')
        st.markdown("---")

    suspect_posts = st.text_area(
        "Paste Mock Recent Post Content Here",
        placeholder="e.g., 'URGENT! Send money now to this wallet address or you will be fined.'",
        height=150
    )
    
    # --- Special Feature Inputs ---
    
    st.subheader("Special Features & Behavioral Analysis")
    
    col_special_1, col_special_2 = st.columns(2)
    
    with col_special_1:
        # NEW FEATURE: Urgency Tone
        urgency_tone_risk = st.selectbox(
            "1. Behavioral: Post Urgency Tone Check (NEW)",
            ("Low Urgency (Normal Inquiry)", "Medium Urgency (Time Pressure)", "High Urgency (Threat/Panic)"),
            index=0,
            key="urgency_check",
            help="High urgency/threat tone contributes significantly to the risk score (Max 15 Points)."
        )

    with col_special_2:
        # NEW FEATURE: Phishing Link Check
        phishing_link_risk = st.selectbox(
            "2. Network: Phishing URL/Homoglyph Check (NEW)",
            ("No Suspicion Detected", "Malicious Domain Structure Detected", "Homoglyph/Typosquatting Detected"),
            index=0,
            key="phishing_check",
            help="Detects subtle typos in URLs mimicking the official site (e.g., using 'rn' instead of 'm'). (Max 3 Points)"
        )
        
    st.subheader("Network Footprint Input")
    
    col_network_1, col_network_2 = st.columns(2)
    
    with col_network_1:
        risk_profile_selection = st.radio(
            "Account Age Check",
            ("High Risk Profile (New/Unestablished Account)", "Low Risk Profile (Established Account)"),
            index=0,
            key="age_check",
            help="A newly created account raises the risk score."
        )
        is_established_account = (risk_profile_selection == "Low Risk Profile (Established Account)")

    with col_network_2:
        # Feature 2: Stolen Profile Picture Check
        profile_pic_stolen = st.selectbox(
            "Profile Picture Origin Check (Stolen Image Detection)",
            ("No (Unique/No Match)", "Yes (Stolen/Official Image Match)"),
            index=0,
            key="pic_check",
            help="If the profile picture is stolen from the official profile, risk increases."
        )
        
    domain_age_risk = st.selectbox(
        "External Link Domain Age Check",
        ("Low Risk (Established Domain)", "Medium Risk (Recently Updated Domain)", "High Risk (New/Suspicious Domain)"),
        index=0,
        key="domain_check",
        help="A newly created or recently updated linked domain suggests higher risk."
    )
    # --- End Special Feature Inputs ---

    if st.button("RUN HAWK-EYE ANALYSIS", use_container_width=True, key="run_button"):
        if not suspect_url or not suspect_handle or not suspect_posts:
            st.error("⚠ Please fill in all input fields to run the analysis.")
            # Clear previous results if new run is incomplete
            if 'final_score' in st.session_state:
                del st.session_state.final_score
        else:
            with st.spinner("Analyzing profile across Identity, Behavior, and Network Modules..."):
                time.sleep(2) # Simulate processing time
                
                # --- Run Analysis ---
                final_score, breakdown = calculate_risk_score(
                    suspect_handle, 
                    suspect_posts, 
                    is_established_account,
                    domain_age_risk,
                    profile_pic_stolen,
                    urgency_tone_risk, # NEW INPUT
                    phishing_link_risk # NEW INPUT
                )
                
                # Store results in session state
                st.session_state.final_score = final_score
                st.session_state.breakdown = breakdown
                st.session_state.suspect_url = suspect_url
                st.session_state.suspect_handle = suspect_handle
                st.session_state.suspect_posts = suspect_posts
                
            st.success("✅ Analysis Complete! See results below.")

# --- Results Display (Conditional, triggered by session state) ---
if 'final_score' in st.session_state:
    # Retrieve data from session state
    final_score = st.session_state.final_score
    breakdown = st.session_state.breakdown
    suspect_url = st.session_state.suspect_url
    suspect_handle = st.session_state.suspect_handle
    suspect_posts = st.session_state.suspect_posts
    confidence_score = breakdown.get("Confidence Score (%)", "N/A")
    
    # Determine Risk Label and Suggestion
    suggestion_text, suggestion_style, risk_label = get_action_suggestion(final_score)

    # --- Results Display in Streamlit ---
    st.markdown("---")
    st.subheader("Final Impersonation Risk Score")
    
    col_gauge, col_confidence = st.columns(2)
    
    with col_gauge:
        st.metric(label="Calculated Risk Score", value=f"{final_score}%", help="A high score indicates high certainty of impersonation.")
        
    with col_confidence:
        st.metric(label="AI Model Confidence", value=f"{confidence_score}%", help="The model's certainty in the accuracy of the calculated risk level.")

    # Display the colored risk box
    css_class = risk_label.split(":")[0].lower().replace(" risk", "").replace(" ", "-") 
    st.markdown(f'<div class="risk-{css_class}">🛑 {risk_label}</div>', unsafe_allow_html=True)
    
    # Display Actionable Intelligence
    st.markdown("---")
    st.subheader("Actionable Intelligence")
    if suggestion_style == "error":
        st.error(suggestion_text)
    elif suggestion_style == "warning":
        st.warning(suggestion_text)
    else:
        st.info(suggestion_text)

    # Display Breakdown Table
    st.markdown("---")
    st.subheader("Analysis Breakdown")
    
    # Prepare data for display with NEW features
    display_breakdown = [
        {"Metric": "Identity Risk Points (Max 45)", "Value": breakdown.get("Identity Risk Points (Max 45)")},
        {"Metric": "Handle Similarity Score (%)", "Value": f"{breakdown.get('Handle Similarity Score (%)')}%"},
        {"Metric": "Keyword Scan Points (Max 25)", "Value": breakdown.get("Keyword Scan Points (Max 25)")},
        {"Metric": "*Urgency Tone Points (NEW)*", "Value": breakdown.get("Urgency Tone Points (Max 15)")},
        {"Metric": "Behavioral Risk Points (Total)", "Value": breakdown.get("Behavioral Risk Points (Max 40)")},
        {"Metric": "Account Age (Days)", "Value": breakdown.get("Account Age (Days)")},
        {"Metric": "Domain Age Risk Points", "Value": breakdown.get("Domain Age Risk Points")},
        {"Metric": "*Phishing Link Points (NEW)*", "Value": breakdown.get("Phishing Link Points")},
        {"Metric": "Stolen Picture Risk Points", "Value": breakdown.get("Stolen Picture Risk Points")},
        {"Metric": "Network/Metadata Risk Points (Total)", "Value": breakdown.get("Network/Metadata Risk Points (Max 15)")},
    ]

    st.dataframe(pd.DataFrame(display_breakdown), use_container_width=True, hide_index=True)


    # --- GENERATE HTML FOR PDF DOWNLOAD ---
    html_content = create_html_report(final_score, breakdown, suspect_url, suspect_handle, suspect_posts, suggestion_text, risk_label)

    # --- FINAL DOWNLOAD BUTTON ---
    st.download_button(
        label="Download Professional Report (HTML)",
        data=html_content,
        file_name="Forensic_Report_HawkEyeAI.html", 
        mime="text/html",
        key="download_button_v4"
    )