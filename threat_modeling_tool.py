import streamlit as st
import json

# Streamlit App Configuration
st.set_page_config(page_title="OWASP Threat Modeling Tool", layout="wide")

# Initialize session state for storing model data
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

# Predefined trust boundaries
PREDEFINED_TRUST_BOUNDARIES = ["Public Network", "Internal Network", "DMZ", "Database Layer", "Application Layer"]

# STRIDE threats and mitigations
STRIDE_THREATS = {
    "Spoofing": {"description": "Pretending to be something or someone else.", "mitigation": "Implement strong authentication mechanisms (e.g., MFA).", "frameworks": {"NIST 800-53": "IA-2, IA-5", "OWASP Top 10": "A07:2021 - Identification and Authentication Failures"}},
    "Tampering": {"description": "Unauthorized modification of data.", "mitigation": "Use integrity checks (e.g., hashes, digital signatures).", "frameworks": {"NIST 800-53": "SI-7", "OWASP Top 10": "A05:2021 - Security Misconfiguration"}},
    "Repudiation": {"description": "Denying an action occurred.", "mitigation": "Implement logging and audit trails.", "frameworks": {"NIST 800-53": "AU-2, AU-3", "OWASP Top 10": "A09:2021 - Security Logging and Monitoring Failures"}},
    "Information Disclosure": {"description": "Unauthorized access to data.", "mitigation": "Encrypt sensitive data in transit and at rest.", "frameworks": {"NIST 800-53": "SC-8, SC-28", "OWASP Top 10": "A02:2021 - Cryptographic Failures"}},
    "Denial of Service": {"description": "Disrupting service availability.", "mitigation": "Implement rate limiting and redundancy.", "frameworks": {"NIST 800-53": "SC-5", "OWASP Top 10": "A04:2021 - Insecure Design"}},
    "Elevation of Privilege": {"description": "Gaining unauthorized access levels.", "mitigation": "Enforce least privilege and role-based access control.", "frameworks": {"NIST 800-53": "AC-6", "OWASP Top 10": "A01:2021 - Broken Access Control"}}
}

def main():
    st.title("OWASP Threat Modeling Teaching Tool")
    st.markdown("Follow the OWASP Threat Modeling Process to create a threat model. Complete each step to build and analyze your system.")

    # Step 1: Diagram the Application
    st.header("Step 1: Diagram the Application")
    st.markdown("Define components (e.g., User, Server) and data flows (e.g., User -> Server). Select or define trust boundaries.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Add Component")
        component_name = st.text_input("Component Name (e.g., User, Server)")
        trust_boundary = st.selectbox("Select Trust Boundary", PREDEFINED_TRUST_BOUNDARIES + ["Custom"])
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
        flow_source = st.selectbox("Source Component", [c["name"] for c in st.session_state.components])
        flow_destination = st.selectbox("Destination Component", [c["name"] for c in st.session_state.components])
        flow_name = st.text_input("Flow Name (e.g., HTTP Request)")
        if st.button("Add Data Flow"):
            if flow_source and flow_destination and flow_name:
                st.session_state.flows.append({"name": flow_name, "source": flow_source, "destination": flow_destination})
                st.success(f"Added flow: {flow_name} ({flow_source} -> {flow_destination})")

    st.subheader("Current Diagram")
    if st.session_state.components or st.session_state.flows:
        diagram = "Components:\n" + "\n".join([f"- {c['name']} (Trust Boundary: {c['trust_boundary']})" for c in st.session_state.components])
        diagram += "\n\nData Flows:\n" + "\n".join([f"- {f['name']}: {f['source']} -> {f['destination']}" for f in st.session_state.flows])
        st.text_area("Diagram", diagram, height=200)
    else:
        st.write("No components or flows added yet.")

    # Step 2: Identify Threats
    st.header("Step 2: Identify Threats")
    st.markdown("Analyze the diagram using the STRIDE framework to identify potential threats.")
    if st.button("Run STRIDE Analysis"):
        st.session_state.threats = []
        for flow in st.session_state.flows:
            source = next(c for c in st.session_state.components if c["name"] == flow["source"])
            dest = next(c for c in st.session_state.components if c["name"] == flow["destination"])
            source_boundary = source["trust_boundary"]
            dest_boundary = dest["trust_boundary"]
            for threat, details in STRIDE_THREATS.items():
                # Only add threats if flow crosses trust boundaries or is within a sensitive boundary
                if source_boundary != dest_boundary or source_boundary in ["Public Network", "DMZ"]:
                    st.session_state.threats.append({
                        "flow": flow["name"],
                        "threat": threat,
                        "description": details["description"],
                        "mitigation": details["mitigation"],
                        "frameworks": details["frameworks"]
                    })
        st.success("STRIDE analysis completed.")

    # Step 3: Review Threats and Mitigations
    st.header("Step 3: Review Threats and Mitigations")
    st.markdown("Review the identified threats and their mitigations. Each threat is mapped to NIST 800-53 and OWASP Top 10.")
    if st.session_state.threats:
        for threat in st.session_state.threats:
            with st.expander(f"Threat: {threat['threat']} on {threat['flow']}"):
                st.write(f"**Description**: {threat['description']}")
                st.write(f"**Mitigation**: {threat['mitigation']}")
                st.write(f"**Security Frameworks**:")
                st.write(f"- NIST 800-53: {threat['frameworks']['NIST 800-53']}")
                st.write(f"- OWASP Top 10: {threat['frameworks']['OWASP Top 10']}")
                custom_mitigation = st.text_input(f"Custom Mitigation for {threat['threat']} on {threat['flow']}", key=f"mit_{threat['flow']}_{threat['threat']}")
                if custom_mitigation:
                    threat["mitigation"] = custom_mitigation
                    st.session_state.mitigations.append({"flow": threat["flow"], "threat": threat["threat"], "mitigation": custom_mitigation})
                    st.success(f"Updated mitigation for {threat['threat']} on {threat['flow']}")
    else:
        st.write("No threats identified yet. Run STRIDE analysis in Step 2.")

    # Step 4: Validate the Model
    st.header("Step 4: Validate the Model")
    st.markdown("Review the model for completeness. Ensure all components, flows, threats, and mitigations are defined.")
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

if __name__ == "__main__":
    main()
