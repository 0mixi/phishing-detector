"""
Train a Random Forest classifier on a phishing URL dataset.

Usage:
    python model/train.py --dataset data/urls.csv

Dataset format (CSV):
    url,label
    http://paypal-secure.tk/login,1
    https://paypal.com,0

Saves trained model to model/phishing_model.pkl
"""

import argparse
import pickle
import csv
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.extractor import extract_features

def load_dataset(path: str):
    X, y = [], []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            features = extract_features(row["url"])
            X.append(list(features.values()))
            y.append(int(row["label"]))
    return X, y

def train(dataset_path: str, model_out: str = "model/phishing_model.pkl"):
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
    except ImportError:
        print("Install scikit-learn: pip install scikit-learn")
        return

    print(f"[*] Loading dataset: {dataset_path}")
    X, y = load_dataset(dataset_path)
    print(f"[*] {len(X)} samples loaded")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n[*] Evaluation on test set:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    Path(model_out).parent.mkdir(exist_ok=True)
    with open(model_out, "wb") as f:
        pickle.dump(clf, f)
    print(f"[✓] Model saved to {model_out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, help="Path to CSV dataset")
    parser.add_argument("--output",  default="model/phishing_model.pkl")
    args = parser.parse_args()
    train(args.dataset, args.output)
