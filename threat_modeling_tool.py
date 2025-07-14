import streamlit as st
import json
import pandas as pd
from streamlit_drawable_canvas import st_canvas
import base64

# Streamlit App Configuration
st.set_page_config(page_title="Enterprise Threat Modeling Tool", layout="wide")

# Initialize session state
if 'components' not in st.session_state:
    st.session_state.components = []
if 'flows' not in st.session_state:
    st.session_state.flows = []
if 'trust_boundaries' not in st.session_state:
    st.session_state.trust_boundaries = []
if 'threats' not in st.session_state:
    st.session_state.threats = []
if 'mitigations' not in st.session_state:
    st.session_state.mitigations = []
if 'flow_counter' not in st.session_state:
    st.session_state.flow_counter = 0

# Predefined trust boundaries
PREDEFINED_TRUST_BOUNDARIES = ["Public Network", "Internal Network", "DMZ", "Database Layer", "Application Layer"]

# Extended STRIDE threats with CAPEC mappings
STRIDE_THREATS = {
    "Spoofing": {
        "description": "Pretending to be something or someone else.",
        "mitigation": "Implement strong authentication mechanisms (e.g., MFA).",
        "frameworks": {"NIST 800-53": "IA-2, IA-5", "OWASP Top 10": "A07:2021 - Identification and Authentication Failures"},
        "capec": "CAPEC-151: Identity Spoofing"
    },
    "Tampering": {
        "description": "Unauthorized modification of data.",
        "mitigation": "Use integrity checks (e.g., hashes, digital signatures).",
        "frameworks": {"NIST 800-53": "SI-7", "OWASP Top 10": "A05:2021 - Security Misconfiguration"},
        "capec": "CAPEC-26: Data Tampering"
    },
    "Repudiation": {
        "description": "Denying an action occurred.",
        "mitigation": "Implement logging and audit trails.",
        "frameworks": {"NIST 800-53": "AU-2, AU-3", "OWASP Top 10": "A09:2021 - Security Logging and Monitoring Failures"},
        "capec": "CAPEC-93: Log Injection"
    },
    "Information Disclosure": {
        "description": "Unauthorized access to data.",
        "mitigation": "Encrypt sensitive data in transit and at rest.",
        "frameworks": {"NIST 800-53": "SC-8, SC-28", "OWASP Top 10": "A02:2021 - Cryptographic Failures"},
        "capec": "CAPEC-116: Data Interception"
    },
    "Denial of Service": {
        "description": "Disrupting service availability.",
        "mitigation": "Implement rate limiting and redundancy.",
        "frameworks": {"NIST 800-53": "SC-5", "OWASP Top 10": "A04:2021 - Insecure Design"},
        "capec": "CAPEC-125: Resource Depletion"
    },
    "Elevation of Privilege": {
        "description": "Gaining unauthorized access levels.",
        "mitigation": "Enforce least privilege and role-based access control.",
        "frameworks": {"NIST 800-53": "AC-6", "OWASP Top 10": "A01:2021 - Broken Access Control"},
        "capec": "CAPEC-233: Privilege Escalation"
    }
}

# Sample threat models
SAMPLE_MODELS = {
    "Web Application": {
        "components": [
            {"name": "User", "trust_boundary": "Public Network"},
            {"name": "Web Server", "trust_boundary": "DMZ"},
            {"name": "Database", "trust_boundary": "Database Layer"}
        ],
        "flows": [
            {"id": 1, "name": "HTTP Request", "source": "User", "destination": "Web Server"},
            {"id": 2, "name": "SQL Query", "source": "Web Server", "destination": "Database"}
        ],
        "trust_boundaries": ["Public Network", "DMZ", "Database Layer"],
        "threats": [
            {"flow_id": 1, "flow": "HTTP Request", "threat": "Spoofing", "description": STRIDE_THREATS["Spoofing"]["description"], "mitigation": "Use MFA and session tokens", "frameworks": STRIDE_THREATS["Spoofing"]["frameworks"], "capec": STRIDE_THREATS["Spoofing"]["capec"]},
            {"flow_id": 1, "flow": "HTTP Request", "threat": "Information Disclosure", "description": STRIDE_THREATS["Information Disclosure"]["description"], "mitigation": "Use HTTPS with TLS 1.3", "frameworks": STRIDE_THREATS["Information Disclosure"]["frameworks"], "capec": STRIDE_THREATS["Information Disclosure"]["capec"]},
            {"flow_id": 2, "flow": "SQL Query", "threat": "Tampering", "description": STRIDE_THREATS["Tampering"]["description"], "mitigation": "Use parameterized queries", "frameworks": STRIDE_THREATS["Tampering"]["frameworks"], "capec": STRIDE_THREATS["Tampering"]["capec"]}
        ],
        "mitigations": [
            {"flow_id": 1, "flow": "HTTP Request", "threat": "Spoofing", "mitigation": "Use MFA and session tokens"},
            {"flow_id": 1, "flow": "HTTP Request", "threat": "Information Disclosure", "mitigation": "Use HTTPS with TLS 1.3"},
            {"flow_id": 2, "flow": "SQL Query", "threat": "Tampering", "mitigation": "Use parameterized queries"}
        ]
    },
    "IoT System": {
        "components": [
            {"name": "IoT Device", "trust_boundary": "Public Network"},
            {"name": "Gateway", "trust_boundary": "Internal Network"},
            {"name": "Cloud Server", "trust_boundary": "Application Layer"}
        ],
        "flows": [
            {"id": 1, "name": "Sensor Data", "source": "IoT Device", "destination": "Gateway"},
            {"id": 2, "name": "API Call", "source": "Gateway", "destination": "Cloud Server"}
        ],
        "trust_boundaries": ["Public Network", "Internal Network", "Application Layer"],
        "threats": [
            {"flow_id": 1, "flow": "Sensor Data", "threat": "Spoofing", "description": STRIDE_THREATS["Spoofing"]["description"], "mitigation": "Device certificate-based authentication", "frameworks": STRIDE_THREATS["Spoofing"]["frameworks"], "capec": STRIDE_THREATS["Spoofing"]["capec"]},
            {"flow_id": 1, "flow": "Sensor Data", "threat": "Denial of Service", "description": STRIDE_THREATS["Denial of Service"]["description"], "mitigation": "Implement rate limiting on device", "frameworks": STRIDE_THREATS["Denial of Service"]["frameworks"], "capec": STRIDE_THREATS["Denial of Service"]["capec"]}
        ],
        "mitigations": [
            {"flow_id": 1, "flow": "Sensor Data", "threat": "Spoofing", "mitigation": "Device certificate-based authentication"},
            {"flow_id": 1, "flow": "Sensor Data", "threat": "Denial of Service", "mitigation": "Implement rate limiting on device"}
        ]
    },
    "API Service": {
        "components": [
            {"name": "Client", "trust_boundary": "Public Network"},
            {"name": "API Gateway", "trust_boundary": "DMZ"},
            {"name": "Backend Service", "trust_boundary": "Application Layer"}
        ],
        "flows": [
            {"id": 1, "name": "API Request", "source": "Client", "destination": "API Gateway"},
            {"id": 2, "name": "Internal Request", "source": "API Gateway", "destination": "Backend Service"}
        ],
        "trust_boundaries": ["Public Network", "DMZ", "Application Layer"],
        "threats": [
            {"flow_id": 1, "flow": "API Request", "threat": "Elevation of Privilege", "description": STRIDE_THREATS["Elevation of Privilege"]["description"], "mitigation": "Use OAuth 2.0 with scope restrictions", "frameworks": STRIDE_THREATS["Elevation of Privilege"]["frameworks"], "capec": STRIDE_THREATS["Elevation of Privilege"]["capec"]},
            {"flow_id": 1, "flow": "API Request", "threat": "Denial of Service", "description": STRIDE_THREATS["Denial of Service"]["description"], "mitigation": "Rate limiting at API Gateway", "frameworks": STRIDE_THREATS["Denial of Service"]["frameworks"], "capec": STRIDE_THREATS["Denial of Service"]["capec"]}
        ],
        "mitigations": [
            {"flow_id": 1, "flow": "API Request", "threat": "Elevation of Privilege", "mitigation": "Use OAuth 2.0 with scope restrictions"},
            {"flow_id": 1, "flow": "API Request", "threat": "Denial of Service", "mitigation": "Rate limiting at API Gateway"}
        ]
    }
}

def create_download_link(data, filename, label):
    """Generate a download link for JSON or CSV data."""
    if filename.endswith('.json'):
        data_str = json.dumps(data, indent=2)
        b64 = base64.b64encode(data_str.encode()).decode()
        href = f'<a href="data:application/json;base64,{b64}" download="{filename}">{label}</a>'
    elif filename.endswith('.csv'):
        df = pd.DataFrame(data)
        csv = df.to_csv(index=False)
        b64 = base64.b64encode(csv.encode()).decode()
        href = f'<a href="data:text/csv;base64,{b64}" download="{filename}">{label}</a>'
    return href

def main():
    st.title("Enterprise Threat Modeling Tool")
    st.markdown("Follow the OWASP Threat Modeling Process to create a threat model. Load a sample model or create your own with visual diagramming.")

    # Load Sample Model
    st.header("Load Sample Threat Model")
    st.markdown("Select a sample model to explore or choose 'None' to start fresh.", help="Sample models include pre-filled components, flows, threats, and mitigations.")
    sample_model = st.selectbox("Select a Sample Model", ["None"] + list(SAMPLE_MODELS.keys()))
    if st.button("Load Sample Model"):
        if sample_model != "None":
            st.session_state.components = SAMPLE_MODELS[sample_model]["components"]
            st.session_state.flows = SAMPLE_MODELS[sample_model]["flows"]
            st.session_state.trust_boundaries = SAMPLE_MODELS[sample_model]["trust_boundaries"]
            st.session_state.threats = SAMPLE_MODELS[sample_model]["threats"]
            st.session_state.mitigations = SAMPLE_MODELS[sample_model]["mitigations"]
            st.session_state.flow_counter = max(f["id"] for f in st.session_state.flows) if st.session_state.flows else 0
            st.success(f"Loaded sample model: {sample_model}")
        else:
            st.session_state.components = []
            st.session_state.flows = []
            st.session_state.trust_boundaries = []
            st.session_state.threats = []
            st.session_state.mitigations = []
            st.session_state.flow_counter = 0
            st.success("Cleared model data")

    # Step 1: Diagram the Application
    st.header("Step 1: Diagram the Application")
    st.markdown("Define components and data flows. Use the canvas to draw a Data Flow Diagram (DFD).", help="Add components and flows below, then use the canvas to visualize them. Drag to draw entities and arrows.")

    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Add Component")
        component_name = st.text_input("Component Name (e.g., User, Server)", help="Enter a unique name for the component.")
        trust_boundary = st.selectbox("Select Trust Boundary", PREDEFINED_TRUST_BOUNDARIES + ["Custom"], help="Choose a trust boundary or define a custom one.")
        custom_boundary = st.text_input("Custom Trust Boundary (if selected)", disabled=trust_boundary != "Custom")
        if st.button("Add Component"):
            if component_name:
                boundary = custom_boundary if trust_boundary == "Custom" and custom_boundary else trust_boundary
                st.session_state.components.append({"name": component_name, "trust_boundary": boundary})
                if boundary not in st.session_state.trust_boundaries and boundary not in PREDEFINED_TRUST_BOUNDARIES:
                    st.session_state.trust_boundaries.append(boundary)
                st.success(f"Added component: {component_name} in {boundary}")
    
    with col2:
        st.subheader("Add Data Flow")
        flow_source = st.selectbox("Source Component", [c["name"] for c in st.session_state.components], key="flow_source")
        flow_destination = st.selectbox("Destination Component", [c["name"] for c in st.session_state.components], key="flow_destination")
        flow_name = st.text_input("Flow Name (e.g., HTTP Request)", help="Name the data flow (e.g., API Request).")
        if st.button("Add Data Flow"):
            if flow_source and flow_destination and flow_name:
                st.session_state.flow_counter += 1
                flow_id = st.session_state.flow_counter
                st.session_state.flows.append({"id": flow_id, "name": flow_name, "source": flow_source, "destination": flow_destination})
                st.success(f"Added flow: {flow_name} ({flow_source} -> {flow_destination})")

    st.subheader("Visual Data Flow Diagram")
    canvas_result = st_canvas(
        fill_color="rgba(0, 165, 255, 0.3)",
        stroke_width=2,
        stroke_color="black",
        background_color="#eee",
        height=300,
        drawing_mode="freedraw",
        key="canvas"
    )
    st.markdown("Draw components (rectangles) and flows (arrows) above. Use text inputs to define details.")

    st.subheader("Current Diagram")
    if st.session_state.components or st.session_state.flows:
        diagram = "Components:\n" + "\n".join([f"- {c['name']} (Trust Boundary: {c['trust_boundary']})" for c in st.session_state.components])
        diagram += "\n\nData Flows:\n" + "\n".join([f"- {f['name']} (ID: {f['id']}): {f['source']} -> {f['destination']}" for f in st.session_state.flows])
        st.text_area("Diagram", diagram, height=200)
    else:
        st.write("No components or flows added yet.")

    # Step 2: Identify Threats
    st.header("Step 2: Identify Threats")
    st.markdown("Analyze the diagram using the STRIDE framework to identify potential threats.", help="STRIDE identifies Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege threats.")
    if st.button("Run STRIDE Analysis"):
        st.session_state.threats = []
        for flow in st.session_state.flows:
            source = next(c for c in st.session_state.components if c["name"] == flow["source"])
            dest = next(c for c in st.session_state.components if c["name"] == flow["destination"])
            source_boundary = source["trust_boundary"]
            dest_boundary = dest["trust_boundary"]
            for threat, details in STRIDE_THREATS.items():
                if source_boundary != dest_boundary or source_boundary in ["Public Network", "DMZ"]:
                    st.session_state.threats.append({
                        "flow_id": flow["id"],
                        "flow": flow["name"],
                        "threat": threat,
                        "description": details["description"],
                        "mitigation": details["mitigation"],
                        "frameworks": details["frameworks"],
                        "capec": details["capec"]
                    })
        st.success("STRIDE analysis completed.")

    # Step 3: Review Threats and Mitigations
    st.header("Step 3: Review Threats and Mitigations")
    st.markdown("Review identified threats, mitigations, and security framework mappings. Add custom mitigations as needed.", help="Each threat includes CAPEC mappings and suggested mitigations.")
    if st.session_state.threats:
        for idx, threat in enumerate(st.session_state.threats):
            with st.expander(f"Threat: {threat['threat']} on {threat['flow']} (Flow ID: {threat['flow_id']})"):
                st.write(f"**Description**: {threat['description']}")
                st.write(f"**Default Mitigation**: {threat['mitigation']}")
                st.write(f"**CAPEC Mapping**: {threat['capec']}")
                st.write(f"**Security Frameworks**:")
                st.write(f"- NIST 800-53: {threat['frameworks']['NIST 800-53']}")
                st.write(f"- OWASP Top 10: {threat['frameworks']['OWASP Top 10']}")
                custom_mitigation = st.text_input(
                    f"Custom Mitigation for {threat['threat']} on {threat['flow']}",
                    key=f"mit_{threat['flow_id']}_{threat['threat']}_{idx}",
                    help="Override the default mitigation if needed."
                )
                if custom_mitigation:
                    threat["mitigation"] = custom_mitigation
                    st.session_state.mitigations.append({
                        "flow_id": threat["flow_id"],
                        "flow": threat["flow"],
                        "threat": threat["threat"],
                        "mitigation": custom_mitigation
                    })
                    st.success(f"Updated mitigation for {threat['threat']} on {threat['flow']}")
    else:
        st.write("No threats identified yet. Run STRIDE analysis in Step 2.")

    # Step 4: Validate the Model
    st.header("Step 4: Validate the Model")
    st.markdown("Review the model for completeness. Ensure all components, flows, threats, and mitigations are defined.", help="Validation checks for missing elements.")
    if st.button("Validate Model"):
        validation = []
        if not st.session_state.components:
            validation.append("No components defined. Add components in Step 1.")
        if not st.session_state.flows:
            validation.append("No data flows defined. Add flows in Step 1.")
        if not st.session_state.threats:
            validation.append("No threats identified. Run STRIDE analysis in Step 2.")
        if not st.session_state.mitigations:
            validation.append("No custom mitigations defined. Add mitigations in Step 3.")
        if validation:
            st.error("\n".join(validation))
        else:
            st.success("Model is complete! All components, flows, threats, and mitigations are defined.")
        
        # Generate final output
        output = {
            "components": st.session_state.components,
            "flows": st.session_state.flows,
            "trust_boundaries": st.session_state.trust_boundaries,
            "threats": st.session_state.threats,
            "mitigations": st.session_state.mitigations
        }
        st.subheader("Final Threat Model")
        st.json(output)
        
        # Download options
        st.subheader("Export Threat Model")
        st.markdown(create_download_link(output, "threat_model.json", "Download as JSON"), unsafe_allow_html=True)
        if st.session_state.threats:
            threat_data = [{"Flow": t["flow"], "Threat": t["threat"], "Description": t["description"], "Mitigation": t["mitigation"], "CAPEC": t["capec"], "NIST 800-53": t["frameworks"]["NIST 800-53"], "OWASP Top 10": t["frameworks"]["OWASP Top 10"]} for t in st.session_state.threats]
            st.markdown(create_download_link(threat_data, "threats.csv", "Download Threats as CSV"), unsafe_allow_html=True)

if __name__ == "__main__":
    main()
