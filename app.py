import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go

class OWASPRiskCalculator:
    def __init__(self):
        self.factors = {
            "Threat Agent Factors": {
                "Skill Level": [
                    "No technical skills",
                    "Some technical skills", 
                    "Advanced computer user",
                    "Network and programming skills",
                    "Security penetration skills"
                ],
                "Motive": [
                    "Low or no reward",
                    "Possible reward", 
                    "High reward"
                ],
                "Opportunity": [
                    "Full access/expensive resource required",
                    "Special access or resource required", 
                    "Some access or resource required",
                    "No access or resource required"
                ],
                "Size": [
                    "Developer",
                    "System administrator", 
                    "Intranet users",
                    "Authenticated users", 
                    "Anonymous internet users"
                ]
            },
            "Vulnerability Factors": {
                "Ease of Discovery": [
                    "Practically impossible",
                    "Difficult", 
                    "Easy", 
                    "Automated tools available"
                ],
                "Ease of Exploit": [
                    "Theoretical", 
                    "Difficult", 
                    "Easy", 
                    "Automated tools available"
                ],
                "Awareness": [
                    "Unknown", 
                    "Hidden", 
                    "Obvious", 
                    "Public knowledge"
                ],
                "Intrusion Detection": [
                    "Active detection in application",
                    "Logged and reviewed", 
                    "Logged without review", 
                    "Not logged"
                ]
            },
            "Technical Impact Factors": {
                "Loss of Confidentiality": [
                    "Minimal non-sensitive data disclosed",
                    "Minimal critical data disclosed", 
                    "Extensive non-sensitive data disclosed",
                    "Extensive critical data disclosed", 
                    "All data disclosed"
                ],
                "Loss of Integrity": [
                    "Minimal slightly corrupt data",
                    "Minimal seriously corrupt data", 
                    "Extensive slightly corrupt data",
                    "Extensive seriously corrupt data", 
                    "All data totally corrupt"
                ],
                "Loss of Availability": [
                    "Minimal secondary services interrupted",
                    "Minimal primary services interrupted", 
                    "Extensive secondary services interrupted",
                    "Extensive primary services interrupted", 
                    "All services completely lost"
                ],
                "Loss of Accountability": [
                    "Fully traceable",
                    "Possibly traceable", 
                    "Completely anonymous"
                ]
            },
            "Business Impact Factors": {
                "Financial Damage": [
                    "Less than the cost to fix the vulnerability",
                    "Minor effect on annual profit", 
                    "Significant effect on annual profit",
                    "Bankruptcy"
                ],
                "Reputation Damage": [
                    "Minimal damage",
                    "Loss of major accounts", 
                    "Loss of goodwill",
                    "Brand damage"
                ],
                "Non-Compliance": [
                    "Minor violation",
                    "Clear violation", 
                    "High profile violation"
                ],
                "Privacy Violation": [
                    "One individual",
                    "Hundreds of people", 
                    "Thousands of people",
                    "Millions of people"
                ]
            }
        }
        
    def calculate_risk(self, selected_factors):
        """
        Calculate risk based on selected factors
        """
        risk_scores = {
            "Threat Agent": 0,
            "Vulnerability": 0,
            "Technical Impact": 0,
            "Business Impact": 0
        }
        
        # Calculate scores for each category
        threat_agent_score = sum(selected_factors.get("Threat Agent Factors", {}).values())
        vulnerability_score = sum(selected_factors.get("Vulnerability Factors", {}).values())
        technical_impact_score = sum(selected_factors.get("Technical Impact Factors", {}).values())
        business_impact_score = sum(selected_factors.get("Business Impact Factors", {}).values())
        
        # Likelihood calculation
        likelihood_score = (threat_agent_score + vulnerability_score) / 2
        
        # Impact calculation
        impact_score = (technical_impact_score + business_impact_score) / 2
        
        # Overall risk calculation
        overall_risk = likelihood_score * impact_score
        
        # Risk level determination
        if overall_risk > 70:
            risk_level = "High Risk"
            risk_color = "red"
        elif overall_risk > 30:
            risk_level = "Medium Risk"
            risk_color = "orange"
        else:
            risk_level = "Low Risk"
            risk_color = "green"
        
        return {
            "likelihood_score": round(likelihood_score, 2),
            "impact_score": round(impact_score, 2),
            "overall_risk": round(overall_risk, 2),
            "risk_level": risk_level,
            "risk_color": risk_color
        }
    
    def render_app(self):
        """
        Streamlit app rendering
        """
        st.title("OWASP Risk Assessment Tool")
        
        # Initialize session state for selected factors
        if 'selected_factors' not in st.session_state:
            st.session_state.selected_factors = {}
        
        # Sidebar for factor selection
        with st.sidebar:
            st.header("Select Risk Factors")
            
            # Iterate through factor categories
            for category, factors in self.factors.items():
                st.subheader(category)
                
                # Create a dictionary to store selected values for this category
                if category not in st.session_state.selected_factors:
                    st.session_state.selected_factors[category] = {}
                
                for factor, options in factors.items():
                    selected = st.selectbox(
                        f"{factor}", 
                        options=options, 
                        key=f"{category}_{factor}"
                    )
                    
                    # Store the index of the selected option
                    st.session_state.selected_factors[category][factor] = options.index(selected)
        
        # Calculate Risk Button
        if st.button("Calculate Risk"):
            # Validate that all factors are selected
            if all(st.session_state.selected_factors.values()):
                risk_result = self.calculate_risk(st.session_state.selected_factors)
                
                # Display Risk Results
                st.header("Risk Assessment Results")
                
                # Create columns for risk metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Likelihood Score", risk_result['likelihood_score'])
                with col2:
                    st.metric("Impact Score", risk_result['impact_score'])
                with col3:
                    st.metric("Overall Risk", risk_result['overall_risk'])
                with col4:
                    st.metric("Risk Level", risk_result['risk_level'], 
                              help="Indicates the severity of the identified risks")
                
                # Visualize Risk Scores
                risk_data = [
                    {"Category": "Threat Agent", "Score": risk_result['likelihood_score']},
                    {"Category": "Vulnerability", "Score": risk_result['likelihood_score']},
                    {"Category": "Technical Impact", "Score": risk_result['impact_score']},
                    {"Category": "Business Impact", "Score": risk_result['impact_score']}
                ]
                
                fig = px.bar(
                    risk_data, 
                    x="Category", 
                    y="Score", 
                    title="Risk Scores by Category",
                    color="Score",
                    color_continuous_scale='RdYlGn'
                )
                st.plotly_chart(fig)
                
                # Risk Mitigation Recommendations
                st.header("Risk Mitigation Recommendations")
                if risk_result['risk_level'] == "High Risk":
                    st.warning("🚨 High Risk Detected! Immediate action required.")
                    st.markdown("""
                    Recommended Actions:
                    - Conduct immediate comprehensive security assessment
                    - Implement urgent mitigation strategies
                    - Develop incident response plan
                    - Allocate resources for comprehensive security overhaul
                    """)
                elif risk_result['risk_level'] == "Medium Risk":
                    st.info("⚠️ Moderate Risk Identified. Proactive measures needed.")
                    st.markdown("""
                    Recommended Actions:
                    - Perform detailed vulnerability analysis
                    - Develop targeted security improvement plan
                    - Prioritize critical vulnerabilities
                    - Enhance monitoring and detection mechanisms
                    """)
                else:
                    st.success("✅ Low Risk. Maintain current security practices.")
                    st.markdown("""
                    Recommended Actions:
                    - Continue regular security assessments
                    - Maintain and update security controls
                    - Conduct periodic vulnerability scans
                    """)
            else:
                st.error("Please select all factors before calculating risk.")

def main():
    calculator = OWASPRiskCalculator()
    calculator.render_app()

if __name__ == "__main__":
    main()