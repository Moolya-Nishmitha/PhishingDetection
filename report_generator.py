# report_generator.py - PDF Report Generation (FIXED)

from fpdf import FPDF
from datetime import datetime

def generate_pdf_report(analysis, filepath):
    """Generate PDF report using fpdf2"""
    
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(0, 100, 150)
    pdf.cell(0, 12, "PHISHING DETECTION REPORT", ln=True, align="C")
    
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", "", 10)
    pdf.ln(5)
    
    # Summary Section
    pdf.set_font("Arial", "B", 11)
    pdf.set_text_color(0, 100, 150)
    pdf.cell(0, 10, "SUMMARY", ln=True)
    
    pdf.set_font("Arial", "", 9)
    pdf.set_text_color(0, 0, 0)
    
    pdf.cell(40, 7, "Type:", border=0)
    pdf.cell(0, 7, analysis['type'], ln=True, border=0)
    
    pdf.cell(40, 7, "Verdict:", border=0)
    pdf.cell(0, 7, analysis['verdict'], ln=True, border=0)
    
    pdf.cell(40, 7, "Risk Score:", border=0)
    pdf.cell(0, 7, f"{analysis['score']}/6", ln=True, border=0)
    
    pdf.cell(40, 7, "Threat Level:", border=0)
    pdf.cell(0, 7, analysis['threat_level'], ln=True, border=0)
    
    pdf.cell(40, 7, "Time:", border=0)
    pdf.cell(0, 7, analysis['timestamp'].strftime("%Y-%m-%d %H:%M"), ln=True, border=0)
    
    pdf.ln(5)
    
    # Analysis Results
    pdf.set_font("Arial", "B", 11)
    pdf.set_text_color(0, 100, 150)
    pdf.cell(0, 10, "ANALYSIS RESULTS", ln=True)
    
    pdf.set_font("Arial", "", 9)
    pdf.set_text_color(0, 0, 0)
    
    if analysis['url_result']:
        pdf.cell(0, 7, f"URL Analysis Score: {analysis['url_result']['score']}", ln=True)
        if analysis['url_result']['reasons']:
            for reason in analysis['url_result']['reasons'][:3]:
                pdf.set_x(15)
                pdf.multi_cell(0, 5, f"- {reason}")
        else:
            pdf.cell(0, 5, "  No URL threats", ln=True)
        pdf.ln(2)
    
    if analysis['content_result']:
        pdf.cell(0, 7, f"Content Analysis Score: {analysis['content_result']['score']}", ln=True)
        if analysis['content_result']['keywords_found']:
            for keyword in analysis['content_result']['keywords_found'][:3]:
                pdf.set_x(15)
                pdf.multi_cell(0, 5, f"- {keyword}")
        else:
            pdf.cell(0, 5, "  No suspicious content", ln=True)
        pdf.ln(2)
    
    ml_text = "PHISHING" if analysis['ml_result'] else "LEGITIMATE"
    pdf.cell(0, 7, f"ML Classifier: {ml_text}", ln=True)
    pdf.ln(5)
    
    # Recommendations
    pdf.set_font("Arial", "B", 11)
    pdf.set_text_color(0, 100, 150)
    pdf.cell(0, 10, "RECOMMENDATIONS", ln=True)
    
    pdf.set_font("Arial", "", 8)
    pdf.set_text_color(0, 0, 0)
    
    for i, rec in enumerate(analysis['recommendations'][:5], 1):
        pdf.set_font("Arial", "B", 9)
        pdf.cell(0, 6, f"{i}. {rec['title']}", ln=True)
        
        pdf.set_font("Arial", "", 8)
        pdf.set_x(15)
        pdf.multi_cell(0, 4, f"{rec['description']}")
        
        pdf.set_x(15)
        pdf.multi_cell(0, 4, f"Action: {rec['action']}")
        pdf.ln(1)
    
    # Footer
    pdf.ln(5)
    pdf.set_font("Arial", "", 7)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 5, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
             ln=True, align="C")
    
    try:
        pdf.output(filepath)
        return True
    except Exception as e:
        print(f"PDF Error: {e}")
        return False