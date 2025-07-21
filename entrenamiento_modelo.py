import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

base_path = os.path.expanduser("~/Desktop/Entrenar Modelo/Datasets")
train_path = os.path.join(base_path, "UNSW_NB15_training-set.csv")
test_path = os.path.join(base_path, "UNSW_NB15_testing-set.csv")

df_train = pd.read_csv(train_path)
df_test = pd.read_csv(test_path)
df = pd.concat([df_train, df_test], ignore_index=True)

features = [
    'dur', 'proto', 'service', 'state',
    'sbytes', 'dbytes', 'sttl', 'dttl',
    'sload', 'dload', 'sloss', 'dloss'
]

X = df[features]
y = df['attack_cat']

X = X.fillna(0)
for col in X.select_dtypes(include=['object']).columns:
    X.loc[:, col] = LabelEncoder().fit_transform(X[col])

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print("\n🔎 Resultados del modelo:\n")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

joblib.dump(clf, "modelo_entrenado.pkl")
joblib.dump(label_encoder, "label_encoder.pkl")
print("✅ Modelo y codificador guardados correctamente.")

