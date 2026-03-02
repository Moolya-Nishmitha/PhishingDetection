import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
from url_analysis import analyze_url
from content_analysis import analyze_content
from ml_model import train_model, ml_predict

# Train model once at startup
print("Training model...")
model, vectorizer = train_model()

def run_analysis():
    user_input = input_box.get("1.0", tk.END).strip()
    if not user_input:
        messagebox.showwarning("Empty Input", "Please enter a URL or email text.")
        return

    url_result     = analyze_url(user_input)
    content_result = analyze_content(user_input)
    ml_result      = ml_predict(user_input, model, vectorizer)
    total_score    = url_result["score"] + content_result["score"] + ml_result

    # Clear previous results
    result_box.config(state=tk.NORMAL)
    result_box.delete("1.0", tk.END)

    # URL findings
    result_box.insert(tk.END, "[ URL ANALYSIS ]\n", "heading")
    result_box.insert(tk.END, f"Score: {url_result['score']}\n")
    if url_result["reasons"]:
        for r in url_result["reasons"]:
            result_box.insert(tk.END, f"  • {r}\n", "warning")
    else:
        result_box.insert(tk.END, "  • No URL threats detected\n", "safe")

    # Content findings
    result_box.insert(tk.END, "\n[ CONTENT ANALYSIS ]\n", "heading")
    result_box.insert(tk.END, f"Score: {content_result['score']}\n")
    if content_result["keywords_found"]:
        for k in content_result["keywords_found"]:
            result_box.insert(tk.END, f"  • {k}\n", "warning")
    else:
        result_box.insert(tk.END, "  • No suspicious content\n", "safe")

    # ML result
    result_box.insert(tk.END, "\n[ ML CLASSIFIER ]\n", "heading")
    ml_text = "⚠ Phishing" if ml_result else "✓ Legitimate"
    tag = "danger" if ml_result else "safe"
    result_box.insert(tk.END, f"  Prediction: {ml_text}\n", tag)

    # Final verdict
    result_box.insert(tk.END, f"\n{'='*40}\n")
    result_box.insert(tk.END, f"TOTAL RISK SCORE: {total_score}\n", "heading")

    if total_score >= 4:
        verdict = "🚨 HIGH RISK — Likely Phishing"
        vtag = "danger"
    elif total_score >= 2:
        verdict = "⚠️  MODERATE RISK — Treat with caution"
        vtag = "warning"
    else:
        verdict = "✅  LOW RISK — Likely Legitimate"
        vtag = "safe"

    result_box.insert(tk.END, f"VERDICT: {verdict}\n", vtag)
    result_box.config(state=tk.DISABLED)

def clear_all():
    input_box.delete("1.0", tk.END)
    result_box.config(state=tk.NORMAL)
    result_box.delete("1.0", tk.END)
    result_box.config(state=tk.DISABLED)

# ── Window setup ──────────────────────────────────────────
root = tk.Tk()
root.title("Phishing Detection System")
root.geometry("700x600")
root.configure(bg="#1e1e2e")
root.resizable(True, True)

FONT_MAIN  = ("Courier New", 11)
FONT_TITLE = ("Courier New", 15, "bold")
BG         = "#1e1e2e"
FG         = "#cdd6f4"
ACCENT     = "#89b4fa"
BTN_BG     = "#313244"

# Title
tk.Label(root, text="🛡 Phishing Detection System",
         font=FONT_TITLE, bg=BG, fg=ACCENT).pack(pady=(15, 5))

tk.Label(root, text="Enter a URL or paste email/message text below:",
         font=FONT_MAIN, bg=BG, fg=FG).pack()

# Input box
input_box = scrolledtext.ScrolledText(root, height=6, font=FONT_MAIN,
                                       bg="#313244", fg=FG,
                                       insertbackground=FG, relief=tk.FLAT)
input_box.pack(fill=tk.X, padx=20, pady=10)

# Buttons
btn_frame = tk.Frame(root, bg=BG)
btn_frame.pack()

tk.Button(btn_frame, text="🔍 Analyze", font=FONT_MAIN,
          bg=ACCENT, fg=BG, padx=20, pady=5,
          command=run_analysis, relief=tk.FLAT).grid(row=0, column=0, padx=10)

tk.Button(btn_frame, text="🗑 Clear", font=FONT_MAIN,
          bg=BTN_BG, fg=FG, padx=20, pady=5,
          command=clear_all, relief=tk.FLAT).grid(row=0, column=1, padx=10)

# Results box
tk.Label(root, text="Analysis Report:", font=FONT_MAIN,
         bg=BG, fg=FG).pack(anchor="w", padx=20, pady=(10, 0))

result_box = scrolledtext.ScrolledText(root, height=16, font=FONT_MAIN,
                                        bg="#181825", fg=FG,
                                        state=tk.DISABLED, relief=tk.FLAT)
result_box.pack(fill=tk.BOTH, expand=True, padx=20, pady=(5, 20))

# Color tags
result_box.tag_config("heading",  foreground=ACCENT,   font=("Courier New", 11, "bold"))
result_box.tag_config("safe",     foreground="#a6e3a1")
result_box.tag_config("warning",  foreground="#f9e2af")
result_box.tag_config("danger",   foreground="#f38ba8")

root.mainloop()
