import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import json
import os

def train_and_save_model():
    print("[*] Loading network_logs.csv...")
    try:
        df = pd.read_csv("network_logs.csv")
    except FileNotFoundError:
        print("[-] network_logs.csv not found! Run dataset_generator.py first.")
        return

    print(f"[*] Dataset shape: {df.shape}")
    print(f"[*] Attack distribution:\n{df['label'].value_counts()}\n")

    # Categorical columns that need encoding
    categorical_cols = ['protocol_type', 'service', 'flag']
    encoders = {}

    print("[*] Preprocessing categorical features...")
    for col in categorical_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        encoders[col] = le
        print(f"    Encoded '{col}': {len(le.classes_)} classes -> {list(le.classes_)}")

    # Separation of features and target
    X = df.drop(columns=['label'])
    y = df['label']
    feature_names = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n[*] Training Random Forest Classifier (100 estimators)...")
    print(f"    Train size: {len(X_train)}, Test size: {len(X_test)}")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # Evaluation
    print("\n[*] Evaluating the model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"[+] Model Accuracy: {accuracy * 100:.2f}%")

    report_dict = classification_report(y_test, y_pred, output_dict=True)
    report_str = classification_report(y_test, y_pred)
    print(report_str)

    # Cross-validation
    print("[*] Running 5-fold cross-validation...")
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
    print(f"[+] CV Accuracy: {cv_scores.mean() * 100:.2f}% (+/- {cv_scores.std() * 100:.2f}%)")

    # Feature importance
    importances = model.feature_importances_
    feature_importance = dict(zip(feature_names, [round(float(v), 4) for v in importances]))
    sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
    print("\n[*] Feature Importance (Top -> Bottom):")
    for feat, imp in sorted_features:
        bar = "#" * int(imp * 50)
        print(f"    {feat:22s}: {imp:.4f} {bar}")

    # Confusion Matrix - save as image
    print("\n[*] Generating confusion matrix...")
    labels = sorted(y.unique())
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    _save_confusion_matrix(cm, labels)

    # Export metrics as JSON (for dashboard consumption)
    metrics = {
        "accuracy": round(accuracy, 4),
        "cv_accuracy_mean": round(float(cv_scores.mean()), 4),
        "cv_accuracy_std": round(float(cv_scores.std()), 4),
        "feature_importance": feature_importance,
        "class_report": {k: v for k, v in report_dict.items() if k not in ['accuracy', 'macro avg', 'weighted avg']},
        "class_labels": labels,
        "confusion_matrix": cm.tolist(),
        "train_size": len(X_train),
        "test_size": len(X_test),
    }
    with open("metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print("[+] Metrics saved to metrics.json")

    # Save model and encoders
    print("[*] Saving model and encoders...")
    joblib.dump(model, 'model.pkl')
    joblib.dump(encoders, 'encoders.pkl')
    print("[+] Model saved: model.pkl")
    print("[+] Encoders saved: encoders.pkl")
    print("\n[+] Training pipeline complete!")


def _save_confusion_matrix(cm, labels):
    """Save confusion matrix as a PNG image using matplotlib."""
    try:
        import matplotlib
        matplotlib.use('Agg')  # Non-interactive backend
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(8, 6))
        im = ax.imshow(cm, interpolation='nearest', cmap='YlOrRd')
        ax.set_title("Confusion Matrix — Auto-SOC Random Forest", fontsize=13, fontweight='bold')
        fig.colorbar(im, ax=ax, shrink=0.8)

        ax.set_xticks(range(len(labels)))
        ax.set_yticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, ha='right')
        ax.set_yticklabels(labels)
        ax.set_xlabel("Predicted Label", fontsize=11)
        ax.set_ylabel("True Label", fontsize=11)

        # Annotate cells with counts
        thresh = cm.max() / 2.0
        for i in range(len(labels)):
            for j in range(len(labels)):
                ax.text(j, i, format(cm[i, j], 'd'),
                        ha="center", va="center",
                        color="white" if cm[i, j] > thresh else "black",
                        fontsize=11)

        plt.tight_layout()
        plt.savefig("confusion_matrix.png", dpi=150)
        plt.close()
        print("[+] Confusion matrix saved: confusion_matrix.png")
    except ImportError:
        print("[!] matplotlib not installed — skipping confusion matrix image. Install with: pip install matplotlib")


if __name__ == "__main__":
    train_and_save_model()
