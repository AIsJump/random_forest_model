import thrember
import joblib
import os
# import pandas as pd
# import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    confusion_matrix,
    ConfusionMatrixDisplay
)

# OUTDATED; DO NOT USE!!!!!!!!!!!!

if __name__ == "__main__":
    print('main process:', os.getpid())
    print('importing training and testing data')
    X_train, y_train = thrember.read_vectorized_features('model_datasets', subset='train')
    X_test, y_test = thrember.read_vectorized_features('model_datasets', subset='test')
    print('complete')

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        n_jobs=-1,
        class_weight="balanced",
        random_state=42
    )

    print('fitting')
    rf.fit(X_train, y_train)
    print('done fitting')

    print('predicting')
    pred = rf.predict(X_test)
    proba = rf.predict_proba(X_test)[:,1]
    print('done predicting')

    print('=== Classification Report ===')
    print(classification_report(y_test, pred))
    print('AUC:', roc_auc_score(y_test, proba))

    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()

    print('\n=== Confusion Matrix Values ===')
    print("TP:", tp)
    print("FP:", fp)
    print("TN:", tn)
    print("FN:", fn)

    TPR = tp / (tp + fn)  # True Positive Rate
    FNR = fn / (tp + fn)  # False Negative Rate
    TNR = tn / (tn + fp)  # True Negative Rate
    FPR = fp / (tn + fp)  # False Positive Rate

    print('\n=== Rates ===')
    print("TPR (Recall):", TPR)
    print("FNR:", FNR)
    print("TNR (Specificity):", TNR)
    print("FPR:", FPR)

    joblib.dump(rf, 'rf_model_team17_ember2024.pkl')
else:
    print('new process:', os.getpid())