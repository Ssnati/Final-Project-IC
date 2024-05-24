import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score


# Cargar los datos
data = pd.read_csv("Phishing_Legitimate_full.csv")

# Eliminar la columna de ID

# Separar características y etiquetas
X = data.drop(columns=["CLASS_LABEL","rid"])
y = data["CLASS_LABEL"]

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


import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from urllib.parse import urlparse

# Función para extraer características de la URL
def extract_features(url):
    parsed_url = urlparse(url)
    url_features = {
        "NumDots": url.count('.'),
        "SubdomainLevel": len(parsed_url.netloc.split('.')),
        "PathLevel": url.count('/'),
        "UrlLength": len(url),
        "NumDash": url.count('-'),
        "NumDashInHostname": parsed_url.netloc.count('-'),
        "AtSymbol": 1 if '@' in url else 0,
        "TildeSymbol": 1 if '~' in url else 0,
        "NumUnderscore": url.count('_'),
        "NumPercent": url.count('%'),
        "NumQueryComponents": len(parsed_url.query.split('&')),
        "NumAmpersand": url.count('&'),
        "NumHash": url.count('#'),
        "NumNumericChars": sum(c.isdigit() for c in url),
        "NoHttps": 1 if not url.startswith('https') else 0,
        "RandomString": 1 if len(parsed_url.path.split('/')[-1]) >= 12 else 0,  # Assuming random strings are at least 12 characters long
        "IpAddress": 1 if parsed_url.netloc.replace('.', '').isdigit() else 0,
        "DomainInSubdomains": 1 if parsed_url.netloc.count(parsed_url.netloc.split('.')[-1]) > 1 else 0,
        "DomainInPaths": 1 if parsed_url.netloc.split('.')[-2] in parsed_url.path else 0,
        "HttpsInHostname": 1 if 'https' in parsed_url.netloc else 0,
        "HostnameLength": len(parsed_url.netloc),
        "PathLength": len(parsed_url.path),
        "QueryLength": len(parsed_url.query),
        "DoubleSlashInPath": 1 if '//' in parsed_url.path else 0,
        # Hasta aca esta bien
        "NumSensitiveWords": 0,  # Agregar función para contar palabras sensibles
        "EmbeddedBrandName": 0,  # Agregar función para detectar nombres de marcas incrustados
        "PctExtHyperlinks": 0.0,  # Agregar función para calcular porcentaje de hipervínculos externos
        "PctExtResourceUrls": 0.0,  # Agregar función para calcular porcentaje de URL de recursos externos
        "ExtFavicon": 0,  # Agregar función para detectar favicon externo
        "InsecureForms": 0,  # Agregar función para detectar formularios no seguros
        "RelativeFormAction": 0,  # Agregar función para detectar acciones de formulario relativas
        "ExtFormAction": 0,  # Agregar función para detectar acciones de formulario externas
        "AbnormalFormAction": 0,  # Agregar función para detectar acciones de formulario anormales
        "PctNullSelfRedirectHyperlinks": 0.0,  # Agregar función para calcular porcentaje de hipervínculos de auto-redirección nulos
        "FrequentDomainNameMismatch": 0,  # Agregar función para detectar discrepancias frecuentes en el nombre de dominio
        "FakeLinkInStatusBar": 0,  # Agregar función para detectar enlaces falsos en la barra de estado
        "RightClickDisabled": 0,  # Agregar función para detectar clic derecho deshabilitado
        "PopUpWindow": 0,  # Agregar función para detectar ventanas emergentes
        "SubmitInfoToEmail": 0,  # Agregar función para detectar envío de información a través de correo electrónico
        "IframeOrFrame": 0,  # Agregar función para detectar iframes o frames
        "MissingTitle": 0,  # Agregar función para detectar título faltante
        "ImagesOnlyInForm": 0,  # Agregar función para detectar imágenes únicamente en formularios
        "SubdomainLevelRT": 0,  # Agregar función temporal relacionada con el nivel del subdominio
        "UrlLengthRT": 0,  # Agregar función temporal relacionada con la longitud de la URL
        "PctExtResourceUrlsRT": 0.0,  # Agregar función temporal relacionada con el porcentaje de URL de recursos externos
        "AbnormalExtFormActionR": 0,  # Agregar función temporal relacionada con acciones de formulario externas anormales
        "ExtMetaScriptLinkRT": 0,  # Agregar función temporal relacionada con meta scripts y enlaces externos
        "PctExtNullSelfRedirectHyperlinksRT": 0.0,  # Agregar función temporal relacionada con el porcentaje de hipervínculos de auto-redirección nulos
    }
    return pd.DataFrame([url_features])

# Función para predecir si la URL es maliciosa
def predict_malicious(url, model):
    # Extraer características de la URL
    url_features = extract_features(url)
    # Realizar la predicción
    prediction = model.predict(url_features)[0]
    # Probabilidad de ser maliciosa
    probability = model.predict_proba(url_features)[0][1]
    return prediction, probability

# Cargar el modelo entrenado
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# URL de ejemplo
url = "https://mermaid.live/edit#pako:eNplULEKwkAM_ZWQuYuIy60KTp26dgm9WGPtRa45ShH_3bO1UDFTeO_lvSRPbNQzOrxpioGnOkAuE7szlBOMGjsJLXj6MgM3JhrgrGA60wsOUFLHYEwODg5KXuEsTI_BSOLgYL9lTsu8g90HLeBI9pdx1X7r5HUMq9dPSiU2k98ILLDn2JP4fNnzI6rRrpy90OXWU14b6_DKOkqm1RQadBYTF5genoxPQm2kfgXZi2ksl081Gi7S4usN5KNifg"

# Predecir si la URL es maliciosa
prediction, probability = predict_malicious(url, model)

if prediction == 1:
    print("La URL es maliciosa con una probabilidad del", round(probability * 100, 2), "%")
else:
    print("La URL no es maliciosa")
    print("La URL es maliciosa con una probabilidad del", round(probability * 100, 2), "%")