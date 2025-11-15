import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from sklearn.cluster import KMeans
from sklearn.neighbors import NearestNeighbors
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from xgboost import XGBClassifier
import joblib

# Step 1: Load CICIDS2017 Dataset
dataset_folder = "Dataset\CICIDS_2017"
dataframes = []

for file in os.listdir(dataset_folder):
    if file.endswith(".csv"):
        df = pd.read_csv(os.path.join(dataset_folder, file))
        df.columns = df.columns.str.strip()
        dataframes.append(df)

df = pd.concat(dataframes, ignore_index=True)

# Step 2: Feature Selection
features = [
    'Flow Duration', 'Total Fwd Packets', 'Fwd Packet Length Mean',
    'Bwd Packet Length Mean', 'Fwd IAT Mean', 'Bwd IAT Mean',
    'Destination Port', 'Flow IAT Mean', 'Fwd Packet Length Max',
    'Bwd Packet Length Max', 'Fwd Packet Length Min'
]


available_features = [f for f in features if f in df.columns]
X = df[available_features].fillna(0)

# Step 3: Normalize
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# --- UNSUPERVISED PHASE ---

# Step 4: K-Means Clustering
kmeans = KMeans(n_clusters=2, random_state=42)
kmeans_labels = kmeans.fit_predict(X_scaled)

# Step 5: KNN-based anomaly scoring
knn = NearestNeighbors(n_neighbors=5)
knn.fit(X_scaled)
distances, _ = knn.kneighbors(X_scaled)
knn_scores = distances.mean(axis=1)

# Step 6: Isolation Forest
iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
iso_labels = iso.fit_predict(X_scaled)
iso_labels = np.where(iso_labels == 1, 0, 1)  # Flip to: 0=normal, 1=anomaly

# Step 7: Combine All Unsupervised Outputs
unsupervised_df = pd.DataFrame(X_scaled, columns=available_features)
unsupervised_df["iso_label"] = iso_labels
unsupervised_df["knn_score"] = knn_scores
unsupervised_df["kmeans_cluster"] = kmeans_labels

# Step 8: Create pseudo-labels (from Isolation Forest)
pseudo_labels = iso_labels

# --- SUPERVISED PHASE ---

# Step 9: Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(
    unsupervised_df.drop(columns=['iso_label']), pseudo_labels, test_size=0.2, random_state=42)

# Step 10: Train Random Forest
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)

# Step 11: Train XGBoost
xgb = XGBClassifier(use_label_encoder=False, eval_metric='logloss')
xgb.fit(X_train, y_train)
xgb_pred = xgb.predict(X_test)

# --- Evaluation Function ---
def evaluate_model(name, y_true, y_pred):
    print(f"\n{name} Evaluation Report:")
    print("-" * 40)
    print(f"Accuracy : {accuracy_score(y_true, y_pred):.4f}")
    print(f"Precision: {precision_score(y_true, y_pred):.4f}")
    print(f"Recall   : {recall_score(y_true, y_pred):.4f}")
    print(f"F1-Score : {f1_score(y_true, y_pred):.4f}")

    print("\nDetailed Classification Report:")
    print(classification_report(y_true, y_pred))

    cm = confusion_matrix(y_true, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm)
    disp.plot(cmap=plt.cm.Blues)
    plt.title(f'{name} Confusion Matrix')
    plt.show()

evaluate_model("Random Forest", y_test, rf_pred)
evaluate_model("XGBoost", y_test, xgb_pred)

# --- Feature Importance: XGBoost ---
xgb_importance = pd.Series(xgb.feature_importances_, index=X_train.columns)
xgb_importance.sort_values().plot(kind='barh', title='XGBoost Feature Importance', figsize=(8,6), color='skyblue')
plt.xlabel('Importance')
plt.tight_layout()
plt.show()

# --- Feature Importance: Random Forest ---
rf_importance = pd.Series(rf.feature_importances_, index=X_train.columns)
rf_importance.sort_values().plot(kind='barh', title='Random Forest Feature Importance', figsize=(8,6), color='orange')
plt.xlabel('Importance')
plt.tight_layout()
plt.show()

# --- K-Means Cluster Distribution ---
plt.figure(figsize=(6,4))
pd.Series(kmeans_labels).value_counts().sort_index().plot(kind='bar', color='purple')
plt.title("KMeans Cluster Distribution")
plt.xlabel("Cluster Label")
plt.ylabel("Count")
plt.xticks(rotation=0)
plt.tight_layout()
plt.show()

# --- KNN Anomaly Score Histogram ---
plt.figure(figsize=(6,4))
plt.hist(knn_scores, bins=50, color='teal', edgecolor='black')
plt.title("KNN Distance (Anomaly Score) Distribution")
plt.xlabel("Average Distance to Neighbors")
plt.ylabel("Frequency")
plt.tight_layout()
plt.show()

# --- Isolation Forest Anomaly Score ---
iso_scores = iso.decision_function(X_scaled)
plt.figure(figsize=(6,4))
plt.hist(iso_scores, bins=50, color='red', edgecolor='black')
plt.title("Isolation Forest Anomaly Scores")
plt.xlabel("Anomaly Score")
plt.ylabel("Frequency")
plt.tight_layout()
plt.show()

# --- Save Models ---
joblib.dump(rf, "ZeroDay_RandomForest.joblib")
joblib.dump(xgb, "ZeroDay_XGBoost.joblib")
joblib.dump(scaler, "ZeroDay_Scaler.joblib")

# --- Save Pseudo Labels Dataset ---
unsupervised_df["pseudo_label"] = pseudo_labels
unsupervised_df.to_csv("zero_day_hybrid_labeled.csv", index=False)

print("✅ Pipeline complete. Models, visualizations, and labeled data saved.")