# gui_pro.py - Professional Phishing Detection Dashboard (UPGRADED)

import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
from datetime import datetime
import json
from url_analysis import analyze_url
from content_analysis import analyze_content
from ml_model import train_model, ml_predict
from recommendations import get_recommendations
from report_generator import generate_pdf_report
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np

# Train model
print("Training ML model...")
model, vectorizer = train_model()

# History & Stats
analysis_history = []
current_analysis = None

def run_analysis():
    global current_analysis, analysis_history
    
    user_input = input_box.get("1.0", tk.END).strip()
    if not user_input:
        messagebox.showwarning("Empty Input", "Please enter a URL or email text.")
        return

    # Determine type
    is_url = user_input.startswith(('http://', 'https://', 'www.')) or ('.' in user_input and ' ' not in user_input)
    analysis_type = "URL" if is_url else "EMAIL"

    # Analyze
    if is_url:
        url_result = analyze_url(user_input)
        content_result = None
        ml_result = ml_predict(user_input, model, vectorizer)
        score = url_result["score"] + ml_result
    else:
        content_result = analyze_content(user_input)
        url_result = None
        ml_result = ml_predict(user_input, model, vectorizer)
        score = content_result["score"] + ml_result

    # Determine verdict
    if score >= 4:
        verdict = "HIGH RISK"
        threat_level = "Critical"
        verdict_color = "#ff3333"
        bg_color = "#3d1a1a"
    elif score >= 2:
        verdict = "MODERATE RISK"
        threat_level = "Medium"
        verdict_color = "#ffaa00"
        bg_color = "#3d2a1a"
    else:
        verdict = "LOW RISK"
        threat_level = "Low"
        verdict_color = "#00ff44"
        bg_color = "#1a3d1a"

    # Get recommendations
    recommendations = get_recommendations(
        score, analysis_type, url_result, content_result, ml_result
    )

    # Store current analysis
    current_analysis = {
        "input": user_input,
        "type": analysis_type,
        "score": score,
        "verdict": verdict,
        "threat_level": threat_level,
        "url_result": url_result,
        "content_result": content_result,
        "ml_result": ml_result,
        "recommendations": recommendations,
        "timestamp": datetime.now(),
        "verdict_color": verdict_color,
        "bg_color": bg_color
    }

    # Update history
    analysis_history.insert(0, {
        "time": datetime.now().strftime("%H:%M"),
        "type": analysis_type,
        "verdict": verdict,
        "score": score
    })
    if len(analysis_history) > 20:
        analysis_history.pop()

    # Display results
    display_results(current_analysis)
    update_history()
    update_threat_gauge(score)

def display_results(analysis):
    result_box.config(state=tk.NORMAL)
    result_box.delete("1.0", tk.END)

    # Background color
    result_box.config(bg=analysis['bg_color'])

    # Header
    result_box.insert(tk.END, "═" * 55 + "\n", "header")
    result_box.insert(tk.END, f"  ANALYSIS REPORT - {analysis['type']}\n", "header")
    result_box.insert(tk.END, "═" * 55 + "\n\n", "header")

    # Big Verdict
    result_box.insert(tk.END, f"  {analysis['verdict']}\n", "big_verdict")
    result_box.insert(tk.END, f"  Threat Level: {analysis['threat_level']}\n", "verdict_sub")
    result_box.insert(tk.END, f"  Risk Score: {analysis['score']}/6\n\n", "verdict_sub")

    # Analysis Details
    result_box.insert(tk.END, "  ─ ANALYSIS BREAKDOWN ─\n", "subheader")
    result_box.insert(tk.END, "\n")
    
    if analysis['url_result']:
        result_box.insert(tk.END, f"  🔗 URL ANALYSIS: {analysis['url_result']['score']}/2\n", "analysis_label")
        if analysis['url_result']['reasons']:
            for reason in analysis['url_result']['reasons']:
                result_box.insert(tk.END, f"     ⚠️  {reason}\n", "warning_text")
        else:
            result_box.insert(tk.END, "     ✓ No threats detected\n", "safe_text")
        result_box.insert(tk.END, "\n")
    
    if analysis['content_result']:
        result_box.insert(tk.END, f"  📧 CONTENT ANALYSIS: {analysis['content_result']['score']}/2\n", "analysis_label")
        if analysis['content_result']['keywords_found']:
            for keyword in analysis['content_result']['keywords_found']:
                result_box.insert(tk.END, f"     ⚠️  {keyword}\n", "warning_text")
        else:
            result_box.insert(tk.END, "     ✓ No threats detected\n", "safe_text")
        result_box.insert(tk.END, "\n")
    
    ml_text = "🚨 PHISHING DETECTED" if analysis['ml_result'] else "✓ LEGITIMATE"
    result_box.insert(tk.END, f"  🤖 ML CLASSIFIER: {ml_text}\n", "ml_label")

    # Risk Meter Visual
    result_box.insert(tk.END, "\n  ─ RISK LEVEL ─\n", "subheader")
    meter_fill = int((analysis['score'] / 6) * 30)
    meter = "  ["
    for i in range(30):
        if i < meter_fill:
            meter += "█"
        else:
            meter += "░"
    meter += "] " + str(analysis['score']) + "/6"
    result_box.insert(tk.END, meter + "\n\n", "risk_meter")

    # Recommendations
    result_box.insert(tk.END, "  ─ RECOMMENDATIONS ─\n", "subheader")
    result_box.insert(tk.END, "\n")
    for i, rec in enumerate(analysis['recommendations'][:4], 1):
        result_box.insert(tk.END, f"  {i}. {rec['title']}\n", "rec_title")
        result_box.insert(tk.END, f"     {rec['description']}\n", "rec_text")
        result_box.insert(tk.END, f"     → {rec['action']}\n\n", "rec_action")

    result_box.insert(tk.END, "═" * 55 + "\n", "header")

    result_box.config(state=tk.DISABLED)

def update_threat_gauge(score):
    """Update animated threat gauge"""
    for widget in gauge_frame.winfo_children():
        widget.destroy()
    
    fig = Figure(figsize=(6, 2), dpi=80, facecolor='#1a1a2e', edgecolor='none')
    ax = fig.add_subplot(111)
    
    # Gauge colors
    colors_list = ['#00ff44', '#ffaa00', '#ff3333']
    
    if score <= 2:
        color = '#00ff44'
        level = "LOW"
    elif score <= 4:
        color = '#ffaa00'
        level = "MODERATE"
    else:
        color = '#ff3333'
        level = "HIGH"
    
    # Create gauge
    theta = np.linspace(0, np.pi, 100)
    r = 1
    
    # Background arc
    ax.plot(np.cos(theta), np.sin(theta), color='#444455', linewidth=20)
    
    # Threat level arc
    threat_angle = (score / 6) * np.pi
    theta_threat = np.linspace(0, threat_angle, 50)
    ax.plot(np.cos(theta_threat), np.sin(theta_threat), color=color, linewidth=20)
    
    # Pointer
    pointer_angle = (score / 6) * np.pi
    ax.arrow(0, 0, 0.7*np.cos(pointer_angle), 0.7*np.sin(pointer_angle), 
             head_width=0.1, head_length=0.1, fc=color, ec=color, linewidth=3)
    
    # Labels
    ax.text(0, -0.3, f"Score: {score}/6", ha='center', fontsize=14, 
            color='#00d4ff', weight='bold')
    ax.text(0, -0.5, level, ha='center', fontsize=12, color=color, weight='bold')
    
    ax.set_xlim(-1.5, 1.5)
    ax.set_ylim(-0.7, 1.3)
    ax.axis('off')
    
    canvas = FigureCanvasTkAgg(fig, master=gauge_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

def update_history():
    """Update history panel"""
    history_box.config(state=tk.NORMAL)
    history_box.delete("1.0", tk.END)
    
    history_box.insert(tk.END, "RECENT ANALYSES\n", "history_header")
    history_box.insert(tk.END, "─" * 28 + "\n\n", "history_header")
    
    if not analysis_history:
        history_box.insert(tk.END, "No analyses yet\n", "safe_text")
    else:
        for item in analysis_history[:15]:
            if "HIGH" in item['verdict']:
                tag = "danger_text"
            elif "MODERATE" in item['verdict']:
                tag = "warning_text"
            else:
                tag = "safe_text"
            
            history_box.insert(tk.END, f"[{item['time']}] {item['type']}\n", "history_time")
            history_box.insert(tk.END, f"{item['verdict']} (Score: {item['score']})\n\n", tag)
    
    history_box.config(state=tk.DISABLED)

def export_pdf():
    """Export current analysis as PDF"""
    if not current_analysis:
        messagebox.showwarning("No Analysis", "Run an analysis first.")
        return
    
    file_path = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")],
        initialfile=f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )
    
    if file_path:
        try:
            success = generate_pdf_report(current_analysis, file_path)
            if success:
                messagebox.showinfo("Success", f"Report saved:\n{file_path}")
            else:
                messagebox.showerror("Error", "Failed to generate PDF")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")

def clear_all():
    input_box.delete("1.0", tk.END)
    result_box.config(state=tk.NORMAL)
    result_box.delete("1.0", tk.END)
    result_box.config(state=tk.DISABLED)
    for widget in gauge_frame.winfo_children():
        widget.destroy()

# ────────────────────────────────────────────────────
# GUI SETUP
# ────────────────────────────────────────────────────

root = tk.Tk()
root.title("Phishing Detection System")
root.geometry("1500x900")
root.configure(bg="#0f0f1e")

BG = "#0f0f1e"
FG = "#ffffff"
ACCENT = "#00d4ff"
CARD_BG = "#1a1a2e"
HEADER_BG = "#16213e"

# ── Header ──
header = tk.Frame(root, bg=HEADER_BG, height=90)
header.pack(fill=tk.X)
header.pack_propagate(False)

tk.Label(header, text="🛡️ PHISHING DETECTION SYSTEM", 
         font=("Segoe UI", 22, "bold"), bg=HEADER_BG, fg=ACCENT).pack(pady=20)

# ── Main Container ──
main = tk.Frame(root, bg=BG)
main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

# ── Left Panel ──
left = tk.Frame(main, bg=BG)
left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))

# Input section
tk.Label(left, text="INPUT", font=("Segoe UI", 13, "bold"), bg=BG, fg=ACCENT).pack(anchor="w", pady=(0, 8))
input_box = scrolledtext.ScrolledText(left, height=5, font=("Consolas", 11), 
                                       bg=CARD_BG, fg=FG, insertbackground=ACCENT, 
                                       relief=tk.FLAT, borderwidth=1)
input_box.pack(fill=tk.X, pady=(0, 12))

# Buttons
btn_frame = tk.Frame(left, bg=BG)
btn_frame.pack(fill=tk.X, pady=(0, 15))

tk.Button(btn_frame, text="🔍 ANALYZE", font=("Segoe UI", 12, "bold"),
          bg=ACCENT, fg="#0f0f1e", padx=25, pady=10, command=run_analysis, 
          relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=(0, 8))

tk.Button(btn_frame, text="📄 EXPORT PDF", font=("Segoe UI", 12, "bold"),
          bg="#00aa44", fg="white", padx=25, pady=10, command=export_pdf, 
          relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=(0, 8))

tk.Button(btn_frame, text="🗑️ CLEAR", font=("Segoe UI", 12, "bold"),
          bg="#444455", fg=FG, padx=25, pady=10, command=clear_all, 
          relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT)

# Results section
tk.Label(left, text="ANALYSIS RESULTS", font=("Segoe UI", 13, "bold"), bg=BG, fg=ACCENT).pack(anchor="w", pady=(0, 8))
result_box = scrolledtext.ScrolledText(left, height=32, font=("Consolas", 10),
                                        bg=CARD_BG, fg=FG, state=tk.DISABLED, 
                                        relief=tk.FLAT, borderwidth=1)
result_box.pack(fill=tk.BOTH, expand=True)

# ── Right Panel (Dashboard) ──
right = tk.Frame(main, bg=BG, width=380)
right.pack(side=tk.RIGHT, fill=tk.BOTH)
right.pack_propagate(False)

# Threat Gauge
tk.Label(right, text="🎯 THREAT GAUGE", font=("Segoe UI", 13, "bold"), bg=BG, fg=ACCENT).pack(anchor="w", pady=(0, 8))
gauge_frame = tk.Frame(right, bg=CARD_BG, height=180)
gauge_frame.pack(fill=tk.X, pady=(0, 15))
gauge_frame.pack_propagate(False)

# History
tk.Label(right, text="📝 ANALYSIS HISTORY", font=("Segoe UI", 13, "bold"), bg=BG, fg=ACCENT).pack(anchor="w", pady=(0, 8))
history_box = scrolledtext.ScrolledText(right, height=35, font=("Consolas", 9),
                                         bg=CARD_BG, fg=FG, state=tk.DISABLED, 
                                         relief=tk.FLAT, borderwidth=1)
history_box.pack(fill=tk.BOTH, expand=True)

# ── Text Tags ──
tags_config = [
    ("header", ACCENT, ("Consolas", 11, "bold")),
    ("subheader", ACCENT, ("Consolas", 10, "bold")),
    ("big_verdict", "#ffffff", ("Consolas", 16, "bold")),
    ("verdict_sub", "#cccccc", ("Consolas", 11)),
    ("analysis_label", ACCENT, ("Consolas", 11, "bold")),
    ("warning_text", "#ffaa00", ("Consolas", 10)),
    ("safe_text", "#00ff44", ("Consolas", 10)),
    ("danger_text", "#ff3333", ("Consolas", 10)),
    ("ml_label", ACCENT, ("Consolas", 11, "bold")),
    ("risk_meter", "#00ff44", ("Consolas", 10, "bold")),
    ("rec_title", ACCENT, ("Consolas", 10, "bold")),
    ("rec_text", "#dddddd", ("Consolas", 9)),
    ("rec_action", "#ffaa00", ("Consolas", 9, "bold")),
    ("history_header", ACCENT, ("Consolas", 10, "bold")),
    ("history_time", "#00d4ff", ("Consolas", 9)),
]

for box in [result_box, history_box]:
    for tag_name, color, font in tags_config:
        box.tag_config(tag_name, foreground=color, font=font)

root.mainloop()