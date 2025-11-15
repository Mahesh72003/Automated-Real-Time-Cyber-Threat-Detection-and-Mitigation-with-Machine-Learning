import pandas as pd
import numpy as np
import os
import joblib
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA

# ------------------- Step 1: Load and Combine CICIDS2017 Data -------------------

data_path = "Dataset\CICIDS_2017"
files = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv"
]

df_list = []
for file in files:
    file_path = os.path.join(data_path, file)
    df = pd.read_csv(file_path)
    df.columns = df.columns.str.strip()

    # Only keep relevant labels: 'DDoS' and 'BENIGN'
    df = df[df["Label"].isin(["DDoS", "BENIGN"])]
    df["attack_label"] = df["Label"].apply(lambda x: 1 if x == "DDoS" else 0)
    df_list.append(df)

# Combine all datasets
df_combined = pd.concat(df_list, ignore_index=True)
print(f"Total data loaded: {df_combined.shape}")

df_combined.replace([np.inf, -np.inf], np.nan, inplace=True)
df_combined.fillna(0, inplace=True)

# ------------------- Step 2: Feature Selection -------------------
features = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Flow Bytes/s", "Flow Packets/s", "Fwd Header Length"]
df_combined = df_combined[features + ["attack_label"]]

df_combined.fillna(df_combined.mean(), inplace=True)

# Split into features (X) and labels (y)
X = df_combined[features]
y = df_combined["attack_label"]

# ------------------- Step 3: Normalize and Apply KMeans Clustering -------------------

# Normalize the data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Apply PCA to reduce to 2D for visualization
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)

# Apply KMeans Clustering
kmeans = KMeans(n_clusters=2, random_state=42)  # We choose 2 clusters: DDoS vs. BENIGN
y_kmeans = kmeans.fit_predict(X_scaled)

# Plot the clusters
plt.figure(figsize=(8, 6))
plt.scatter(X_pca[:, 0], X_pca[:, 1], c=y_kmeans, cmap='viridis', alpha=0.7)
plt.title("Cluster Visualization using PCA (KMeans Clustering)")
plt.xlabel("Principal Component 1")
plt.ylabel("Principal Component 2")
plt.colorbar(label="Cluster Label")
plt.grid(True)

# Save the plot as an image
plot_path = "Module_Training/DDOS_Attack/cluster_visualization.png"
plt.savefig(plot_path)  # Save as PNG image
plt.close()  # Close the plot to avoid display if not needed

print(f"Cluster visualization saved at: {plot_path}")

# ------------------- Step 4: Train kNN Model -------------------

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Train kNN model with k=5
knn = KNeighborsClassifier(n_neighbors=5)
knn.fit(X_train, y_train)

# Test the model
y_pred = knn.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("Classification Report:")
print(classification_report(y_test, y_pred))

# Save the model
joblib.dump(knn, "Module_Training/DDOS_Attack/ddos_model.pkl")
joblib.dump(scaler, "Module_Training/DDOS_Attack/ddos_scaler.pkl")
print("Model and scaler saved!")