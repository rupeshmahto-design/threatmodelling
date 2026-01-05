"""
AI-Powered Threat Modeling Tool
Enterprise-grade threat assessment platform with Claude AI
"""

import streamlit as st
import anthropic
import os
import io
from datetime import datetime
from pathlib import Path
import json
import base64

# Page configuration
st.set_page_config(
    page_title="AI Threat Modeling Tool",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for beautiful UI
st.markdown("""
    <style>
    .main {
        background-color: #f8f9fa;
    }
    .stButton>button {
        background-color: #1976D2;
        color: white;
        border-radius: 8px;
        padding: 0.5rem 2rem;
        font-weight: 600;
        border: none;
        transition: all 0.3s;
    }
    .stButton>button:hover {
        background-color: #115293;
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    .upload-box {
        border: 2px dashed #1976D2;
        border-radius: 8px;
        padding: 2rem;
        text-align: center;
        background-color: #E3F2FD;
        margin: 1rem 0;
    }
    .risk-badge-critical {
        background-color: #8B0000;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    .risk-badge-high {
        background-color: #FF4500;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    .risk-badge-medium {
        background-color: #FFA500;
        color: black;
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    .risk-badge-low {
        background-color: #228B22;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    .framework-card {
        background: white;
        padding: 1.5rem;
        border-radius: 8px;
        border: 2px solid #E0E0E0;
        margin: 0.5rem 0;
        transition: all 0.3s;
    }
    .framework-card:hover {
        border-color: #1976D2;
        box-shadow: 0 4px 12px rgba(25, 118, 210, 0.15);
    }
    .framework-card.selected {
        border-color: #1976D2;
        background-color: #E3F2FD;
    }
    .stat-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        text-align: center;
        margin: 0.5rem;
    }
    .stat-number {
        font-size: 2.5rem;
        font-weight: bold;
        margin: 0.5rem 0;
    }
    .stat-label {
        font-size: 0.9rem;
        opacity: 0.9;
    }
    h1 {
        color: #1976D2;
        font-weight: 700;
    }
    h2 {
        color: #424242;
        font-weight: 600;
        margin-top: 2rem;
    }
    .header-subtitle {
        color: #757575;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'assessment_complete' not in st.session_state:
    st.session_state.assessment_complete = False
if 'threat_report' not in st.session_state:
    st.session_state.threat_report = None
if 'uploaded_files' not in st.session_state:
    st.session_state.uploaded_files = []
if 'processing' not in st.session_state:
    st.session_state.processing = False

# Threat Modeling Frameworks
FRAMEWORKS = {
    "MITRE ATT&CK": {
        "description": "Comprehensive framework for understanding cyber adversary behavior",
        "focus": "Tactics, Techniques, and Procedures (TTPs)",
        "best_for": "Advanced threat modeling, APT analysis, comprehensive security assessments",
        "coverage": ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", 
                     "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"]
    },
    "STRIDE": {
        "description": "Microsoft's threat modeling methodology",
        "focus": "Six threat categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)",
        "best_for": "Software development, API security, application security",
        "coverage": ["Spoofing Identity", "Tampering with Data", "Repudiation", "Information Disclosure", 
                     "Denial of Service", "Elevation of Privilege"]
    },
    "PASTA": {
        "description": "Process for Attack Simulation and Threat Analysis",
        "focus": "Risk-centric approach with seven stages",
        "best_for": "Risk-based threat modeling, business-aligned security",
        "coverage": ["Define Objectives", "Define Technical Scope", "Application Decomposition", 
                     "Threat Analysis", "Vulnerability Analysis", "Attack Modeling", "Risk & Impact Analysis"]
    },
    "OCTAVE": {
        "description": "Operationally Critical Threat, Asset, and Vulnerability Evaluation",
        "focus": "Organizational risk assessment",
        "best_for": "Enterprise risk management, asset-based threat modeling",
        "coverage": ["Build Asset-Based Threat Profiles", "Identify Infrastructure Vulnerabilities", 
                     "Develop Security Strategy and Plans"]
    },
    "VAST": {
        "description": "Visual, Agile, and Simple Threat modeling",
        "focus": "Scalable threat modeling for agile development",
        "best_for": "DevSecOps, continuous threat modeling, large organizations",
        "coverage": ["Application Threat Models", "Operational Threat Models", "Infrastructure Models"]
    }
}

# Risk Focus Areas
RISK_AREAS = {
    "Agentic AI Risk": {
        "description": "Risks from autonomous AI agents and systems",
        "threats": [
            "Prompt injection and jailbreaking",
            "Unauthorized actions by autonomous agents",
            "Model hallucinations and incorrect decisions",
            "Data poisoning and training manipulation",
            "Agent-to-agent communication security",
            "Privilege escalation by AI agents",
            "Loss of human oversight and control"
        ]
    },
    "Model Risk": {
        "description": "Risks associated with AI/ML model deployment and operations",
        "threats": [
            "Model drift and degradation",
            "Adversarial attacks on models",
            "Model inversion and extraction",
            "Bias and fairness issues",
            "Model supply chain attacks",
            "Insufficient model validation",
            "Model versioning and rollback issues"
        ]
    },
    "Data Security Risk": {
        "description": "Risks related to data confidentiality, integrity, and availability",
        "threats": [
            "Data breaches and exfiltration",
            "Unauthorized access to sensitive data",
            "Data tampering and corruption",
            "Insufficient encryption",
            "Data residency violations",
            "PII exposure",
            "Data retention and disposal issues"
        ]
    },
    "Infrastructure Risk": {
        "description": "Risks in underlying technology infrastructure",
        "threats": [
            "Cloud misconfigurations",
            "Network vulnerabilities",
            "Container and orchestration risks",
            "API security weaknesses",
            "Insufficient monitoring",
            "Denial of service vulnerabilities",
            "Third-party integration risks"
        ]
    },
    "Compliance Risk": {
        "description": "Regulatory and compliance-related risks",
        "threats": [
            "GDPR violations",
            "PCI-DSS non-compliance",
            "HIPAA violations",
            "SOX control failures",
            "Industry-specific regulation gaps",
            "Audit trail insufficiencies",
            "Data sovereignty issues"
        ]
    }
}

def extract_text_from_file(uploaded_file):
    """Extract text content from uploaded files"""
    try:
        file_extension = Path(uploaded_file.name).suffix.lower()
        
        if file_extension in ['.txt', '.md']:
            return uploaded_file.getvalue().decode('utf-8')
        elif file_extension == '.pdf':
            # For PDF, we'll just note the filename and ask Claude to understand it's a PDF
            return f"[PDF Document: {uploaded_file.name}]"
        else:
            return f"[{file_extension.upper()} Document: {uploaded_file.name}]"
    except Exception as e:
        return f"[Error reading {uploaded_file.name}: {str(e)}]"

def generate_threat_assessment(project_info, documents_content, framework, risk_areas, api_key):
    """Generate comprehensive threat assessment using Claude AI"""
    
    client = anthropic.Anthropic(api_key=api_key)
    
    # Build comprehensive prompt
    prompt = f"""You are an expert cybersecurity consultant specializing in threat modeling and risk assessment. 
Perform a comprehensive threat assessment for the following project using the {framework} framework.

**PROJECT INFORMATION:**
- Project Name: {project_info['name']}
- Application Type: {project_info['app_type']}
- Deployment Model: {project_info['deployment']}
- Business Criticality: {project_info['criticality']}
- Compliance Requirements: {', '.join(project_info['compliance'])}

**UPLOADED DOCUMENTATION:**
{documents_content}

**THREAT MODELING FRAMEWORK:** {framework}
{FRAMEWORKS[framework]['description']}

**SPECIFIC RISK FOCUS AREAS TO ASSESS:**
{chr(10).join([f"- {area}: {RISK_AREAS[area]['description']}" for area in risk_areas])}

**ASSESSMENT REQUIREMENTS:**

Please generate a comprehensive threat assessment report with the following structure:

# EXECUTIVE SUMMARY
- Overall Risk Rating (Critical/High/Medium/Low)
- Top 5 Critical Findings
- Key Recommendations (prioritized)
- Assessment Scope and Methodology

# THREAT MODELING ANALYSIS - {framework}

For each relevant category in {framework}, provide:
- Threat Description
- Attack Scenarios
- Risk Rating (Likelihood x Impact)
- Affected Components
- Recommendations

# SPECIALIZED RISK ASSESSMENTS

For each of the following risk areas, provide detailed analysis:

{chr(10).join([f'''
## {area}
Assess the following specific threats:
{chr(10).join([f"- {threat}" for threat in RISK_AREAS[area]['threats']])}

For each threat:
- Current exposure level
- Potential impact
- Specific mitigations
- Detection strategies
''' for area in risk_areas])}

# COMPONENT-SPECIFIC ANALYSIS

Analyze threats by system components:
- Frontend/User Interface
- Backend/Application Layer
- Database/Data Layer
- API/Integration Layer
- Infrastructure/Cloud
- AI/ML Components (if applicable)

# ATTACK SCENARIOS & KILL CHAINS

Provide 3-5 realistic attack scenarios showing:
- Attack path from initial access to impact
- Required attacker capabilities
- Detection opportunities
- Mitigation strategies

# RISK ASSESSMENT MATRIX

Create a detailed risk matrix with:
- Likelihood ratings (1-5)
- Impact ratings (1-5)
- Risk scores
- Priority classification

# PRIORITIZED RECOMMENDATIONS

Organize recommendations by priority:
- **P0 - Critical (0-30 days):** Immediate action required
- **P1 - High (30-90 days):** Short-term priorities
- **P2 - Medium (90-180 days):** Medium-term improvements
- **P3 - Low (180+ days):** Long-term enhancements

For each recommendation:
- Specific action items
- Expected effort
- Expected impact
- Dependencies

# SECURITY CONTROLS MAPPING

Map recommended controls to:
- Preventive Controls
- Detective Controls
- Corrective Controls
- Compensating Controls

# COMPLIANCE CONSIDERATIONS

Map findings to compliance requirements:
{chr(10).join([f"- {req}" for req in project_info['compliance']])}

# METRICS AND KPIs

Recommend:
- Security metrics to track
- KPIs for improvement
- Monitoring priorities

# APPENDICES

- Threat taxonomy reference
- Risk rating methodology
- Tool and technology recommendations
- Additional resources

**OUTPUT FORMAT:**
- Use clear markdown formatting
- Include tables for matrices and mappings
- Use bullet points for lists
- Highlight critical findings with bold text
- Use risk level indicators: CRITICAL, HIGH, MEDIUM, LOW

Generate the complete, detailed threat assessment report now.
"""

    # Call Claude API
    try:
        # Ensure prompt starts with the required Human turn for Claude
        if not (prompt.startswith("\n\nHuman:") or prompt.startswith("\n\nSystem:") or prompt.startswith("Human:") or prompt.startswith("System:")):
            final_prompt = f"\n\nHuman: {prompt}\n\nAssistant:"
        else:
            final_prompt = prompt

        # Save a short preview of the formatted prompt for debugging (visible only on error)
        try:
            preview = final_prompt[:300]
            # Store in session_state for retrieval in the exception handler
            setattr(st.session_state, '_debug_prompt_preview', preview)
        except Exception:
            # Non-fatal if session state isn't writable in some test contexts
            _debug_prompt_preview = final_prompt[:300]

        # Use the Anthropic completions API for this client version
        completion = client.completions.create(
            model="claude-sonnet-4-20250514",
            prompt=final_prompt,
            max_tokens_to_sample=16000,
            temperature=0,
        )

        # The Completion object exposes the generated text on `.completion`
        return getattr(completion, "completion", str(completion))
    except Exception as e:
        # Show the error and include a prompt preview to help diagnose formatting issues
        st.error(f"Error generating threat assessment: {str(e)}")
        preview = getattr(st.session_state, '_debug_prompt_preview', None) if hasattr(st, 'session_state') else None
        if not preview:
            # Fallback if session_state wasn't set
            preview = globals().get('_debug_prompt_preview', None)
        if preview:
            st.error(f"Formatted prompt preview (first 300 chars): {repr(preview)}")
        else:
            st.error("Formatted prompt preview not available")
        return None

def create_pdf_download(report_content, project_name):
    """Create PDF download link"""
    # For now, we'll create a text file that can be easily converted to PDF
    # In production, use a proper PDF library like ReportLab
    
    filename = f"Threat_Assessment_{project_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.md"
    
    return filename, report_content

def main():
    # Header
    st.markdown("""
        <div style='text-align: center; padding: 2rem 0;'>
            <h1>🔒 AI-Powered Threat Modeling Tool</h1>
            <p class='header-subtitle'>Enterprise-grade threat assessment powered by Claude AI</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("### ⚙️ Configuration")
        
        # API Key input
        api_key = st.text_input(
            "Anthropic API Key",
            type="password",
            help="Enter your Anthropic API key to enable threat assessment"
        )
        
        if api_key:
            st.success("✓ API Key configured")
        else:
            st.warning("⚠️ Please enter your API key to continue")
        
        st.markdown("---")
        
        # Navigation
        st.markdown("### 📋 Quick Navigation")
        st.markdown("""
        - [Project Setup](#project-information)
        - [Upload Documents](#upload-project-documents)
        - [Select Framework](#select-threat-modeling-framework)
        - [Risk Areas](#select-risk-focus-areas)
        - [Generate Report](#generate-threat-assessment)
        """)
        
        st.markdown("---")
        
        # Help
        st.markdown("### 💡 Help")
        with st.expander("How to use this tool"):
            st.markdown("""
            1. **Enter API Key:** Add your Anthropic API key
            2. **Project Info:** Fill in project details
            3. **Upload Documents:** Add architecture diagrams, design docs, etc.
            4. **Select Framework:** Choose your threat modeling approach
            5. **Select Risks:** Pick specific risk areas to assess
            6. **Generate:** Click to create your threat assessment
            7. **Download:** Get your PDF report
            """)
        
        with st.expander("Supported Documents"):
            st.markdown("""
            - Architecture Diagrams (PNG, JPG, PDF)
            - Design Documents (PDF, DOCX, TXT, MD)
            - Network Diagrams (PNG, JPG, PDF)
            - Data Flow Diagrams (PNG, JPG, PDF)
            - API Specifications (YAML, JSON, MD)
            - Technical Documentation (PDF, MD, TXT)
            """)
    
    # Main content
    if not api_key:
        st.info("👈 Please enter your Anthropic API key in the sidebar to get started")
        st.markdown("""
        ### Get Your API Key
        1. Visit [Anthropic Console](https://console.anthropic.com/)
        2. Create an account or sign in
        3. Generate an API key
        4. Paste it in the sidebar
        """)
        return
    
    # Project Information
    st.markdown("## 📊 Project Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        project_name = st.text_input(
            "Project Name *",
            placeholder="e.g., Customer Portal Application",
            help="Enter the name of the project to assess"
        )
        
        app_type = st.selectbox(
            "Application Type *",
            ["Web Application", "Mobile Application", "API/Microservice", 
             "Desktop Application", "Cloud Service", "IoT System", "AI/ML Platform"]
        )
        
        deployment = st.selectbox(
            "Deployment Model *",
            ["Cloud (AWS)", "Cloud (Azure)", "Cloud (GCP)", "Cloud (Multi-Cloud)",
             "On-Premises", "Hybrid", "Edge Computing"]
        )
    
    with col2:
        criticality = st.selectbox(
            "Business Criticality *",
            ["Critical", "High", "Medium", "Low"],
            help="Impact if this system is compromised"
        )
        
        compliance = st.multiselect(
            "Compliance Requirements",
            ["PCI-DSS", "GDPR", "HIPAA", "SOX", "ISO 27001", "SOC 2", 
             "NIST", "FedRAMP", "APRA CPS 234"],
            help="Select all applicable compliance requirements"
        )
        
        environment = st.selectbox(
            "Environment",
            ["Production", "Staging", "Development", "UAT", "DR/Backup"]
        )
    
    # Upload Documents
    st.markdown("## 📁 Upload Project Documents")
    
    st.markdown("""
        <div class='upload-box'>
            <h3>📤 Drop your files here</h3>
            <p>Supported formats: PDF, DOCX, TXT, MD, PNG, JPG, YAML, JSON</p>
        </div>
    """, unsafe_allow_html=True)
    
    uploaded_files = st.file_uploader(
        "Choose files",
        accept_multiple_files=True,
        type=['pdf', 'docx', 'txt', 'md', 'png', 'jpg', 'jpeg', 'yaml', 'json'],
        help="Upload architecture diagrams, design documents, data flow diagrams, etc.",
        label_visibility="collapsed"
    )
    
    if uploaded_files:
        st.success(f"✓ {len(uploaded_files)} file(s) uploaded")
        
        # Show uploaded files
        with st.expander("📋 Uploaded Files", expanded=True):
            for idx, file in enumerate(uploaded_files, 1):
                col1, col2, col3 = st.columns([3, 1, 1])
                with col1:
                    st.write(f"{idx}. {file.name}")
                with col2:
                    st.write(f"{file.size / 1024:.1f} KB")
                with col3:
                    st.write(Path(file.name).suffix.upper())
    
    # Select Threat Modeling Framework
    st.markdown("## 🎯 Select Threat Modeling Framework")
    
    framework_cols = st.columns(2)
    
    selected_framework = None
    
    for idx, (framework, details) in enumerate(FRAMEWORKS.items()):
        col = framework_cols[idx % 2]
        
        with col:
            is_selected = st.checkbox(
                framework,
                key=f"framework_{framework}",
                help=details['description']
            )
            
            if is_selected:
                selected_framework = framework
                
                st.markdown(f"""
                <div class='framework-card selected'>
                    <h4>{framework}</h4>
                    <p><strong>Focus:</strong> {details['focus']}</p>
                    <p><strong>Best For:</strong> {details['best_for']}</p>
                    <details>
                        <summary><strong>Coverage Areas</strong></summary>
                        <ul>
                            {''.join([f'<li>{area}</li>' for area in details['coverage']])}
                        </ul>
                    </details>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class='framework-card'>
                    <h4>{framework}</h4>
                    <p>{details['description'][:100]}...</p>
                </div>
                """, unsafe_allow_html=True)
    
    # Select Risk Focus Areas
    st.markdown("## 🎲 Select Risk Focus Areas")
    
    st.markdown("""
    Select the specific risk areas you want to focus on in your threat assessment.
    These will receive detailed analysis in the final report.
    """)
    
    selected_risks = []
    
    risk_cols = st.columns(2)
    
    for idx, (risk_area, details) in enumerate(RISK_AREAS.items()):
        col = risk_cols[idx % 2]
        
        with col:
            is_selected = st.checkbox(
                risk_area,
                value=True,  # Selected by default
                key=f"risk_{risk_area}",
                help=details['description']
            )
            
            if is_selected:
                selected_risks.append(risk_area)
                
                with st.expander(f"Threats covered in {risk_area}"):
                    for threat in details['threats']:
                        st.markdown(f"- {threat}")
    
    # Generate Assessment
    st.markdown("## 🚀 Generate Threat Assessment")
    
    # Validation
    can_generate = (
        project_name and 
        selected_framework and 
        len(selected_risks) > 0 and
        uploaded_files
    )
    
    if not can_generate:
        missing = []
        if not project_name:
            missing.append("Project Name")
        if not selected_framework:
            missing.append("Threat Modeling Framework")
        if len(selected_risks) == 0:
            missing.append("At least one Risk Focus Area")
        if not uploaded_files:
            missing.append("Project Documents")
        
        st.warning(f"⚠️ Please complete the following: {', '.join(missing)}")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        if st.button(
            "🎯 Generate Threat Assessment Report",
            disabled=not can_generate,
            use_container_width=True
        ):
            st.session_state.processing = True
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                # Step 1: Process documents
                status_text.text("📄 Processing uploaded documents...")
                progress_bar.progress(20)
                
                documents_content = ""
                for file in uploaded_files:
                    content = extract_text_from_file(file)
                    documents_content += f"\n\n### {file.name}\n{content}"
                
                # Step 2: Prepare project info
                status_text.text("📊 Preparing project information...")
                progress_bar.progress(40)
                
                project_info = {
                    'name': project_name,
                    'app_type': app_type,
                    'deployment': deployment,
                    'criticality': criticality,
                    'compliance': compliance if compliance else ['None specified'],
                    'environment': environment
                }
                
                # Step 3: Generate assessment
                status_text.text("🤖 Generating threat assessment with Claude AI...")
                progress_bar.progress(60)
                
                threat_report = generate_threat_assessment(
                    project_info,
                    documents_content,
                    selected_framework,
                    selected_risks,
                    api_key
                )
                
                if threat_report:
                    progress_bar.progress(100)
                    status_text.text("✅ Assessment complete!")
                    
                    st.session_state.threat_report = threat_report
                    st.session_state.assessment_complete = True
                    st.session_state.processing = False
                    
                    st.success("🎉 Threat assessment generated successfully!")
                    st.balloons()
                else:
                    st.error("❌ Failed to generate assessment. Please try again.")
                    st.session_state.processing = False
                    
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
                st.session_state.processing = False
    
    # Display Results
    if st.session_state.assessment_complete and st.session_state.threat_report:
        st.markdown("---")
        st.markdown("## 📋 Threat Assessment Report")
        
        # Download buttons
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            filename, content = create_pdf_download(
                st.session_state.threat_report,
                project_name
            )
            
            st.download_button(
                label="📥 Download Report (Markdown)",
                data=content,
                file_name=filename,
                mime="text/markdown",
                use_container_width=True
            )
        
        with col2:
            if st.button("🔄 Generate New Assessment", use_container_width=True):
                st.session_state.assessment_complete = False
                st.session_state.threat_report = None
                st.rerun()
        
        with col3:
            if st.button("📧 Share Report", use_container_width=True):
                st.info("Email sharing coming soon!")
        
        # Display report
        st.markdown("---")
        st.markdown(st.session_state.threat_report)

if __name__ == "__main__":
    main()
