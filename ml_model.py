from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Expanded training data (50 samples — good for undergrad demo)
TRAINING_DATA = [
    ("Verify your bank account immediately or it will be suspended", 1),
    ("You have won a lottery prize claim it now", 1),
    ("Security alert: unusual login detected update your password", 1),
    ("Dear customer your account has been compromised click here", 1),
    ("Urgent: confirm your details or account will be closed", 1),
    ("You have been selected for a special prize act now", 1),
    ("Your PayPal account is limited verify immediately", 1),
    ("IMPORTANT: Your card has been blocked click to unblock", 1),
    ("Dear user click here to claim your reward", 1),
    ("Win a free iPhone enter your credit card details", 1),
    ("Account suspended due to suspicious activity login now", 1),
    ("Final warning: update your billing information today", 1),
    ("Congratulations you won $1000 claim your prize", 1),
    ("Your Netflix account will expire renew now to continue", 1),
    ("Security breach detected confirm identity immediately", 1),
    ("Meeting scheduled for Tuesday at 10am", 0),
    ("Please find attached the project report for review", 0),
    ("Hi team the sprint review is at 3pm today", 0),
    ("Your order has been shipped tracking number below", 0),
    ("Thanks for applying we will review your resume", 0),
    ("The quarterly results have been published on the portal", 0),
    ("Reminder: submit your timesheet by Friday", 0),
    ("Welcome to the team your onboarding starts Monday", 0),
    ("The conference call link has been updated", 0),
    ("Your subscription receipt for this month is attached", 0),
    ("Please review the document and share your feedback", 0),
    ("Happy birthday hope you have a great day", 0),
    ("The library book you reserved is ready for pickup", 0),
    ("Lunch at 1pm today near the office?", 0),
    ("Your flight booking confirmation is attached", 0),
]

def train_model():
    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]

    vectorizer = TfidfVectorizer(ngram_range=(1, 2))
    X = vectorizer.fit_transform(texts)

    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.2, random_state=42
    )

    model = LogisticRegression()
    model.fit(X_train, y_train)

    # Print accuracy report (looks great in demo)
    y_pred = model.predict(X_test)
    print("\n--- ML Model Training Report ---")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    return model, vectorizer

def ml_predict(text: str, model, vectorizer) -> int:
    vec = vectorizer.transform([text])
    return int(model.predict(vec)[0])