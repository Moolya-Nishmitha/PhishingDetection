# recommendations.py - AI Recommendations Engine

def get_recommendations(score, analysis_type, url_result, content_result, ml_result):
    """Generate smart recommendations based on analysis"""
    
    recommendations = []
    
    if score >= 4:
        # HIGH RISK
        if analysis_type == "URL":
            recommendations.extend([
                {
                    "title": "DO NOT CLICK THIS LINK",
                    "description": "This URL has multiple phishing indicators",
                    "action": "Report to your email provider immediately"
                },
                {
                    "title": "Verify Directly",
                    "description": "If expecting communication from this sender, contact them directly",
                    "action": "Call the organization using a verified phone number"
                },
                {
                    "title": "Report Phishing",
                    "description": "Help protect others by reporting this",
                    "action": "Forward to phishing@apwg.org or your email provider's phishing report"
                }
            ])
        else:
            recommendations.extend([
                {
                    "title": "DO NOT RESPOND",
                    "description": "This email is attempting to manipulate you",
                    "action": "Delete immediately and mark as spam/phishing"
                },
                {
                    "title": "Never Share Credentials",
                    "description": "Legitimate organizations NEVER ask for passwords via email",
                    "action": "Be suspicious of urgency and credential requests"
                },
                {
                    "title": "Check Your Account Directly",
                    "description": "If concerned about your account, log in independently",
                    "action": "Go directly to the website without clicking email links"
                }
            ])
    
    elif score >= 2:
        # MODERATE RISK
        recommendations.extend([
            {
                "title": "Be Cautious",
                "description": "This has some phishing characteristics",
                "action": "Verify sender identity before taking action"
            },
            {
                "title": "Don't Provide Sensitive Info",
                "description": "Even if it seems legitimate, be careful with personal data",
                "action": "Never give passwords, SSN, or financial info via email"
            },
            {
                "title": "Hover Before Clicking",
                "description": "Check where the link actually goes",
                "action": "Hover over links to see the real URL before clicking"
            }
        ])
    
    else:
        # LOW RISK
        recommendations.extend([
            {
                "title": "Likely Legitimate",
                "description": "This appears to be a genuine communication",
                "action": "Safe to proceed with normal caution"
            },
            {
                "title": "Stay Vigilant",
                "description": "Even legitimate-looking emails can be spoofed",
                "action": "Always verify unusual requests independently"
            }
        ])
    
    # Add specific recommendations based on what was detected
    if url_result and url_result["reasons"]:
        if "IP address" in str(url_result["reasons"]):
            recommendations.append({
                "title": "IP Address Detected",
                "description": "Legitimate sites use domain names, not IPs",
                "action": "Avoid clicking this link - major phishing indicator"
            })
        
        if "HTTP" in str(url_result["reasons"]):
            recommendations.append({
                "title": "Insecure Protocol",
                "description": "Site doesn't use HTTPS encryption",
                "action": "Never enter sensitive info on HTTP sites"
            })
    
    if content_result and content_result["keywords_found"]:
        if any("sensitive info" in str(k).lower() for k in content_result["keywords_found"]):
            recommendations.append({
                "title": "Asking for Sensitive Data",
                "description": "Legitimate orgs never request credentials via email",
                "action": "This is a major red flag - definitely phishing"
            })
        
        if any("urgent" in str(k).lower() or "immediate" in str(k).lower() for k in content_result["keywords_found"]):
            recommendations.append({
                "title": "Using Urgency Tactic",
                "description": "Phishers use time pressure to bypass your thinking",
                "action": "Take a breath - don't rush into clicking suspicious links"
            })
    
    if ml_result == 1:
        recommendations.append({
            "title": "ML Model Flagged This",
            "description": "Pattern matching trained on real phishing emails",
            "action": "High confidence this is malicious - treat with suspicion"
        })
    
    return recommendations if recommendations else [
        {
            "title": "No Specific Alerts",
            "description": "This appears safe based on current analysis",
            "action": "Standard email caution applies"
        }
    ]