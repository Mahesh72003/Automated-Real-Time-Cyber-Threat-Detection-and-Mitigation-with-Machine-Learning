import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, roc_curve
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os
from glob import glob

# Set random seed for reproducibility
np.random.seed(42)

def load_multiple_files(file_patterns):
    """Load multiple CSV files matching given patterns"""
    dfs = []
    for pattern in file_patterns:
        files = glob(pattern)
        if not files:
            print(f"No files found matching pattern: {pattern}")
            continue
        for file in files:
            try:
                df = pd.read_csv(file)

                # Strip spaces from column names
                df.columns = df.columns.str.strip()

                # Print the unique values of the 'Label' column to understand the format
                print(f"Unique values in 'Label' column in {file}: {df['Label'].unique()}")

                # Identify label column (case insensitive)
                label_col = [col for col in df.columns if col.lower() == 'label']

                if not label_col:
                    print(f"No 'Label' column found in {file}")
                    continue
                label_col = label_col[0]

                # Mark the attacks (using multiple attack types and marking them as 1, others as 0)
                df['is_attack'] = df[label_col].apply(
                    lambda x: 1 if any(attack in str(x) for attack in ['Brute Force', 'DDoS', 'PortScan',
                                                                   'FTP-Patator', 'SSH-Patator',
                                                                   'Web Attack', 'Infiltration'])
                    else 0 if x == 'BENIGN' else np.nan
                )

                # Print the class distribution of the 'is_attack' column
                print(f"Class distribution in {file}:")
                print(df['is_attack'].value_counts())

                # Drop any rows with NaN in 'is_attack' (which means they aren't BruteForce or BENIGN)
                df = df.dropna(subset=['is_attack'])

                dfs.append(df)
                print(f"Loaded {file} with {len(df)} records")
            except Exception as e:
                print(f"Error loading {file}: {str(e)}")

    if not dfs:
        raise ValueError("No valid data files found")

    return pd.concat(dfs, ignore_index=True)



def preprocess_data(df):
    """Preprocess the combined dataframe"""
    # Handle infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop columns with all NaN values
    df.dropna(axis=1, how='all', inplace=True)

    # Fill remaining NaN with 0 (could use other strategies)
    df.fillna(0, inplace=True)

    # Drop non-numeric columns except those we need
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if 'is_attack' in numeric_cols:
        numeric_cols.remove('is_attack')

    # Keep only numeric features and our target
    df = df[numeric_cols + ['is_attack']]

    return df

def train_and_evaluate(df, output_dir='model_output'):
    """Train and evaluate the model"""
    os.makedirs(output_dir, exist_ok=True)

    # Split into features and target
    X = df.drop(columns=['is_attack'])
    y = df['is_attack']

    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y)

    # Initialize and train Random Forest classifier
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )

    print("\nTraining model...")
    rf.fit(X_train, y_train)

    # Make predictions
    y_pred = rf.predict(X_test)
    y_pred_proba = rf.predict_proba(X_test)[:, 1]

    # Evaluate model
    print("\nModel Evaluation:")
    print(classification_report(y_test, y_pred))
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("ROC AUC Score:", roc_auc_score(y_test, y_pred_proba))

    # Confusion matrix
    plt.figure(figsize=(8, 6))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Benign', 'BruteForce'],
                yticklabels=['Benign', 'BruteForce'])
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'))
    plt.close()

    # ROC Curve
    fpr, tpr, thresholds = roc_curve(y_test, y_pred_proba)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc_score(y_test, y_pred_proba):.2f})')
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend()
    plt.savefig(os.path.join(output_dir, 'Graph pic/roc_curve.png'))
    plt.close()

    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': rf.feature_importances_
    }).sort_values('importance', ascending=False)

    plt.figure(figsize=(12, 8))
    sns.barplot(x='importance', y='feature',
                data=feature_importance.head(20))
    plt.title('Top 20 Important Features for Brute Force Detection')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'Graph pic/feature_importance.png'))
    plt.close()

    # Save the model and feature importance
    model_path = os.path.join(output_dir, 'Module_Training/bruteforce_Attack/brute_force_detector_rf.pkl')
    joblib.dump(rf, model_path)

    feature_importance_path = os.path.join(output_dir, 'Module_Training/bruteforce_Attack/feature_importance.csv')
    feature_importance.to_csv(feature_importance_path, index=False)

    print(f"\nModel saved to {model_path}")
    print(f"Feature importance saved to {feature_importance_path}")

    return rf, feature_importance

if __name__ == "__main__":
    # File patterns for brute force attacks (Tuesday has SSH, Wednesday has FTP)
    file_patterns = [
        'Dataset/CICIDS_2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',  # Contains SSH-BruteForce
        'Dataset/CICIDS_2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
        'Dataset/CICIDS_2017/Wednesday-workingHours.pcap_ISCX.csv',
        'Dataset/CICIDS_2017/Tuesday-WorkingHours.pcap_ISCX.csv',
        'Dataset/CICIDS_2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
        'Dataset/CICIDS_2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
        'Dataset/CICIDS_2017/Monday-WorkingHours.pcap_ISCX.csv',
        'Dataset/CICIDS_2017/Friday-WorkingHours-Morning.pcap_ISCX.csv'# Contains FTP-BruteForce
    ]

    try:
        print("Loading and combining data files...")
        df = load_multiple_files(file_patterns)

        print("\nPreprocessing data...")
        df = preprocess_data(df)

        print(f"\nFinal dataset contains {len(df)} records")
        print("Class distribution:")
        print(df['is_attack'].value_counts())

        # Train and evaluate model
        model, feature_importance = train_and_evaluate(df)

        # Print top features
        print("\nTop 20 Important Features for Brute Force Detection:")
        print(feature_importance.head(20))

    except Exception as e:
        print(f"Error: {e}")