import os
import json
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
import joblib
from parse_features import json_to_Svector, load_jsonl_to_matrix
from features_config import FEATURE_KEYS


class MalwareRandomForest:
    def __init__(self, n_estimators=400, random_state=42, test_size=0.2):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=40, # limit depth to prevent overfitting, tune as needed
            random_state=random_state,
            n_jobs=-1,
            class_weight="balanced",
            verbose=1
        )
        self.random_state = random_state
        self.test_size = test_size
        self.is_trained = False
        self.feature_count = None
    
    def load_data_from_files(self, goodware_jsonl, malware_jsonl):
        print(f"Loading goodware data from {goodware_jsonl}...")
        X_goodware = load_jsonl_to_matrix(goodware_jsonl)
        print(f"  Loaded {X_goodware.shape[0]} goodware samples")
        
        print(f"Loading malware data from {malware_jsonl}...")
        X_malware = load_jsonl_to_matrix(malware_jsonl)
        print(f"  Loaded {X_malware.shape[0]} malware samples")
        
        # combine data: goodware = 0, malware = 1
        X = np.vstack([X_goodware, X_malware])
        y = np.hstack([np.zeros(X_goodware.shape[0]), np.ones(X_malware.shape[0])])
        
        self.feature_count = X.shape[1]
        print(f"\nTotal samples: {X.shape[0]}")
        print(f"Feature count: {X.shape[1]}")
        print(f"Class distribution: {np.sum(y==0)} goodware, {np.sum(y==1)} malware")
        
        return X, y
    
    def load_data_from_directory(self, goodware_dir, malware_dir):
        X_list = []
        y_list = []
        
        # load goodware files
        goodware_path = Path(goodware_dir)
        goodware_files = list(goodware_path.glob("*.jsonl"))
        print(f"Found {len(goodware_files)} goodware JSONL file(s)")
        
        for jsonl_file in goodware_files:
            print(f"  Loading {jsonl_file.name}...")
            X_gw = load_jsonl_to_matrix(str(jsonl_file))
            X_list.append(X_gw)
            y_list.append(np.zeros(X_gw.shape[0]))
            print(f"    Loaded {X_gw.shape[0]} samples")
        
        # load malware files
        malware_path = Path(malware_dir)
        malware_files = list(malware_path.glob("*.jsonl"))
        print(f"Found {len(malware_files)} malware JSONL file(s)")
        
        for jsonl_file in malware_files:
            print(f"  Loading {jsonl_file.name}...")
            X_mw = load_jsonl_to_matrix(str(jsonl_file))
            X_list.append(X_mw)
            y_list.append(np.ones(X_mw.shape[0]))
            print(f"    Loaded {X_mw.shape[0]} samples")
        
        X = np.vstack(X_list)
        y = np.hstack(y_list)
        
        self.feature_count = X.shape[1]
        print(f"\nTotal samples: {X.shape[0]}")
        print(f"Feature count: {X.shape[1]}")
        print(f"Class distribution: {np.sum(y==0)} goodware, {np.sum(y==1)} malware")
        
        return X, y
    
    def train(self, X, y, test_size=None):
        if test_size is None:
            test_size = self.test_size
        
        # split data; can just set data split value to arbitrary small value to use all data for training
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=self.random_state, stratify=y
        )
        
        print(f"\nTraining/test split: {len(X_train)} train, {len(X_test)} test")
        print(f"Training Random Forest with {self.model.n_estimators} trees...")
        
        # train model
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # evaluate
        print("\nModel evaluation:")
        y_pred_train = self.model.predict(X_train)
        y_pred_test = self.model.predict(X_test)
        
        train_acc = accuracy_score(y_train, y_pred_train)
        test_acc = accuracy_score(y_test, y_pred_test)
        
        print(f"  Training accuracy: {train_acc:.4f}")
        print(f"  Testing accuracy: {test_acc:.4f}")
        print(f"  Testing precision: {precision_score(y_test, y_pred_test):.4f}")
        print(f"  Testing recall: {recall_score(y_test, y_pred_test):.4f}")
        print(f"  Testing F1 score: {f1_score(y_test, y_pred_test):.4f}")
        
        cm = confusion_matrix(y_test, y_pred_test)
        print(f"\nConfusion Matrix:")
        print(f"  True Negatives (goodware): {cm[0,0]}")
        print(f"  False Positives (goodware misclassified): {cm[0,1]}")
        print(f"  False Negatives (malware missed): {cm[1,0]}")
        print(f"  True Positives (malware detected): {cm[1,1]}")
        
        # feature importance
        print(f"\nTop 10 most important features:")
        feature_importance = self.model.feature_importances_
        top_indices = np.argsort(feature_importance)[-10:][::-1]

        # map vector indices back to feature names
        # NOTE: json_to_vector drops 'sha256',
        # so reconstruct the feature name list accordingly.
        feature_names = []
        for key in FEATURE_KEYS:
            if key == "sha256":
                continue
            feature_names.append(key)

        if len(feature_names) != len(feature_importance):
            print("[WARN] Feature name count does not match model feature count.")

        for i, idx in enumerate(top_indices, 1):
            name = feature_names[idx] if idx < len(feature_names) else f"feature_{idx}"
            print(f"  {i}. {name} (index {idx}): {feature_importance[idx]:.4f}")
    
    def predict(self, X):
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        return self.model.predict(X)
    
    def predict_proba(self, X):
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        return self.model.predict_proba(X)
    
    def save(self, filepath):
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        joblib.dump(self.model, filepath)
        print(f"Model saved to {filepath}")
    
    def load(self, filepath):
        self.model = joblib.load(filepath)
        self.is_trained = True
        print(f"Model loaded from {filepath}")


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="Train random forest malware detector")
    ap.add_argument("--goodware", default="goodware_data/goodware.jsonl", help="Goodware JSONL file")
    ap.add_argument("--malware", default="malware_data/malware.jsonl", help="Malware JSONL file")
    ap.add_argument("--from-dir", action="store_true", help="Load all JSONL files from directories instead")
    ap.add_argument("--goodware-dir", default="goodware_data", help="Goodware directory (with --from-dir)")
    ap.add_argument("--malware-dir", default="malware_data", help="Malware directory (with --from-dir)")
    ap.add_argument("--test-size", type=float, default=0.2, help="Test set fraction")
    ap.add_argument("--save-model", help="Save trained model to file")
    args = ap.parse_args()
    
    rf = MalwareRandomForest(test_size=args.test_size)
    
    if args.from_dir:
        X, y = rf.load_data_from_directory(args.goodware_dir, args.malware_dir)
    else:
        X, y = rf.load_data_from_files(args.goodware, args.malware)
    
    rf.train(X, y)
    
    if args.save_model:
        rf.save(args.save_model)
