import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
import numpy as np
import joblib
import os
from datetime import datetime


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.model_path = 'ml/models/anomaly_detector.model'
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                import joblib
                self.model = joblib.load(self.model_path)
                print("Loaded existing anomaly detection model")
            except:
                print("Could not load model, will train new one")
                self.train_model()
        else:
            self.train_model()

    def train_model(self):
        print("Training new anomaly detection model")
        np.random.seed(42)

        # Normal network traffic (mostly low port numbers)
        normal_ports = np.random.randint(1, 1024, size=(800, 1))
        normal_bytes = np.random.randint(40, 1500, size=(800, 1))
        normal_data = np.hstack([normal_ports, normal_bytes])

        # Anomalous traffic (high ports or unusual packet sizes)
        anomalous_ports = np.random.randint(1024, 65535, size=(50, 1))
        anomalous_bytes = np.random.randint(2000, 9000, size=(50, 1))
        anomalous_data = np.hstack([anomalous_ports, anomalous_bytes])

        # Combine data
        X_train = np.vstack([normal_data, anomalous_data])

        # Train isolation forest
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.model.fit(X_train)

        # Save the model
        os.makedirs('ml/models', exist_ok=True)
        import joblib
        joblib.dump(self.model, self.model_path)
        print("Model trained and saved")

    def extract_features(self, log):
        """Extract features from log for anomaly detection - returns exactly 2 features"""
        features = []

        # Feature 1: Destination port (if available)
        if 'dst_port' in log:
            features.append(log['dst_port'])
        else:
            features.append(0)  # Default value

        # Feature 2: Message length (if available)
        if 'message' in log:
            features.append(len(log['message']))
        else:
            features.append(0)  # Default value

        # Return exactly 2 features to match the trained model
        return np.array(features).reshape(1, -1)

    def detect_anomalies(self, log):
        if not self.model:
            return []

        try:
            features = self.extract_features(log)
            prediction = self.model.predict(features)
            score = self.model.decision_function(features)[0]

            if prediction[0] == -1:  # Anomaly detected
                return [{
                    'type': 'ml_anomaly',
                    'score': float(score),
                    'timestamp': datetime.now().isoformat(),
                    'features': features.tolist()[0]
                }]
        except Exception as e:
            print(f"Error in anomaly detection: {e}")

        return []