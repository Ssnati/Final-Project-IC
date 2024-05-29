import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# Cargar los datos
data = pd.read_csv("Phishing_Legitimate_full.csv")

# Especificar las columnas a mantener
columns_to_keep = ["NumDots", "PathLevel", "UrlLength", "NumDash", "NumQueryComponents", "NumAmpersand",
                   "NumNumericChars", "NumDashInHostname", "PathLength", "QueryLength", "SubdomainLevel",
                   "NumSensitiveWords", "PctExtHyperlinks", "PctExtResourceUrls", "ExtFavicon", "InsecureForms",
                   "PctNullSelfRedirectHyperlinks", "FrequentDomainNameMismatch", "SubmitInfoToEmail",
                   "IframeOrFrame", "ExtMetaScriptLinkRT", "PctExtNullSelfRedirectHyperlinksRT", "CLASS_LABEL"]

# Filtrar las columnas especificadas
filtered_data = data[columns_to_keep]

# Separar características (X) y la etiqueta (y)
X = filtered_data.drop(columns=["CLASS_LABEL"])
y = filtered_data["CLASS_LABEL"]

# Dividir los datos en conjuntos de entrenamiento y prueba
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Inicializar el clasificador Random Forest
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)

# Entrenar el modelo
rf_classifier.fit(X_train, y_train)

# Predecir en el conjunto de prueba
y_pred = rf_classifier.predict(X_test)

# Calcular la precisión
accuracy = accuracy_score(y_test, y_pred)
print("Precisión del modelo:", accuracy)

# Guardar el modelo
joblib.dump(rf_classifier, "url-model.pkl")
