from url_analysis import analyze_url
from content_analysis import analyze_content
from ml_model import train_model, ml_predict

def print_separator():
    print("=" * 50)

def run_detector(model, vectorizer):
    print_separator()
    print("     PHISHING DETECTION SYSTEM")
    print_separator()
    print("Enter a URL or paste email/message text.")
    print("Type 'quit' to exit.\n")

    while True:
        user_input = input("Input: ").strip()

        if user_input.lower() == "quit":
            print("Exiting. Stay safe online!")
            break

        if not user_input:
            continue

        url_result     = analyze_url(user_input)
        content_result = analyze_content(user_input)
        ml_result      = ml_predict(user_input, model, vectorizer)

        total_score = url_result["score"] + content_result["score"] + ml_result

        print("\n--- ANALYSIS REPORT ---")

        print(f"\n[URL Analysis]  Score: {url_result['score']}")
        if url_result["reasons"]:
            for r in url_result["reasons"]:
                print(f"  • {r}")
        else:
            print("  • No URL threats detected")

        print(f"\n[Content Analysis]  Score: {content_result['score']}")
        if content_result["keywords_found"]:
            for k in content_result["keywords_found"]:
                print(f"  • {k}")
        else:
            print("  • No suspicious content detected")

        print(f"\n[ML Classifier]  Prediction: {'⚠ Phishing' if ml_result else '✓ Legitimate'}")

        print(f"\n[TOTAL RISK SCORE]  {total_score}")
        print_separator()

        if total_score >= 4:
            print("🚨 VERDICT: HIGH RISK — Likely Phishing")
        elif total_score >= 2:
            print("⚠️  VERDICT: MODERATE RISK — Treat with caution")
        else:
            print("✅  VERDICT: LOW RISK — Likely Legitimate")

        print_separator()
        print()

if __name__ == "__main__":
    print("Training ML model...")
    model, vectorizer = train_model()
    run_detector(model, vectorizer)