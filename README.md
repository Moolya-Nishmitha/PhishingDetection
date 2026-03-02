# 🛡️ Phishing Detection System

A hybrid phishing detection tool combining **rule-based analysis**, **NLP keyword detection**, and a **Machine Learning classifier** to identify phishing URLs and email content.

> Built as a final year undergraduate project.

---

## 🚀 Features

- 🔗 **URL Analysis** — detects IP-based URLs, suspicious TLDs, misleading domains, insecure protocols
- 📧 **Content Analysis** — identifies phishing keywords, scare tactics, sensitive info requests
- 🤖 **ML Classifier** — Logistic Regression trained on labeled email data using TF-IDF features
- 🖥️ **GUI** — clean dark-themed desktop interface built with Tkinter
- 💻 **CLI** — also runs as a command-line tool

---

## 📁 Project Structure
```
PhishingDetection/
├── gui.py
├── url_analysis.py
├── content_analysis.py
├── ml_model.py
├── main.py
└── requirements.txt
```

---

## ⚙️ Setup & Run

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/PhishingDetection.git
cd PhishingDetection
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run GUI
```bash
python gui.py
```

### 4. Run CLI
```bash
python main.py
```

---

## 🧠 How It Works

The system uses a **hybrid detection approach** combining three layers:

| Layer | Method | What it detects |
|-------|--------|-----------------|
| URL Analysis | Rule-based | Suspicious domains, IP use, insecure protocol |
| Content Analysis | Pattern matching | Phishing keywords, scare language, sensitive data requests |
| ML Classifier | Logistic Regression + TF-IDF | Overall phishing vs legitimate classification |

Risk scores from all three layers are combined into a **total risk score**:

- **Score ≥ 4** → 🚨 High Risk
- **Score 2–3** → ⚠️ Moderate Risk  
- **Score < 2** → ✅ Low Risk

---


## 📚 References

- Scikit-learn documentation — https://scikit-learn.org
- APWG Phishing Trends Report
- UCI ML Repository — Phishing Websites Dataset