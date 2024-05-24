import re
import requests
from urllib.parse import urlparse, parse_qs
import joblib
import pandas as pd
from bs4 import BeautifulSoup


# Colores de texto
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

# Colores de fondo
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"
BG_MAGENTA = "\033[45m"
BG_CYAN = "\033[46m"
BG_WHITE = "\033[47m"

# Estilos
RESET = "\033[0m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"


def obtener_numero_de_palabras_sensibles(url):
    palabras_sensibles = ['phishing', 'password', 'login', 'bank', 'paypal']  # Lista de palabras sensibles
    return sum(1 for palabra in palabras_sensibles if palabra in url.lower())


def obtener_nombre_de_marca_incrustado(url):
    marcas_incrustadas = ['google', 'facebook', 'twitter', 'amazon']  # Lista de marcas incrustadas
    return sum(1 for marca in marcas_incrustadas if marca in url.lower())


# Función para extraer características de la URL
def calculate_pct_ext_hyperlinks(url_to_extract):
    try:
        response = requests.get(url_to_extract)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            num_ext_hyperlinks = len([link for link in soup.find_all('a') if 'http' in link.get('href')])
            num_hyperlinks = len(soup.find_all('a'))
            return (num_ext_hyperlinks / num_hyperlinks) * 100
        else:
            print("Error al obtener el contenido de la URL. Código de estado:", response.status_code)
            return 0.0
    except Exception as e:
        print("Error al calcular el porcentaje de hipervínculos externos:", e)
    return 0.0  # Dummy value


def ensure_scheme(url):
    url_parsed = urlparse(url)
    if not url_parsed.scheme:
        url = 'http://' + url
    if not url_parsed.netloc:
        url = url.replace('http://', 'http://www.')
        url = url.replace('https://', 'https://www.')
    return url


def extract_features(url_to_extract):
    url_to_extract = ensure_scheme(url_to_extract)
    parsed_url = urlparse(url_to_extract)
    print(f"{RED}Contenido de la URL parseada: {RESET}", parsed_url)
    url_features = {
        "NumDots": url_to_extract.count('.'),
        "SubdomainLevel": len(parsed_url.hostname.split('.')) - 2,
        "PathLevel": len(parsed_url.path.split('/')),
        "UrlLength": len(url_to_extract),
        "NumDash": url_to_extract.count('-'),
        "NumDashInHostname": parsed_url.hostname.count('-'),
        # "AtSymbol": 1 if '@' in url else 0,
        # "TildeSymbol": 1 if '~' in url else 0,
        "NumUnderscore": url_to_extract.count('_'),
        "NumPercent": url_to_extract.count('%'),
        "NumQueryComponents": len(parse_qs(parsed_url.query)),
        "NumAmpersand": url_to_extract.count('&'),
        # "NumHash": url.count('#'),
        "NumNumericChars": sum(c.isdigit() for c in url_to_extract),
        # "NoHttps": 0 if url.startswith('https') else 1,
        "RandomString": 1 if len(parsed_url.path.split('/')[-1]) >= 12 else 0,  # 12 es un umbral arbitrario
        # "IpAddress": 1 if parsed_url.netloc.replace('.', '').isdigit() else 0,
        # "DomainInSubdomains": 1 if parsed_url.netloc.count(parsed_url.netloc.split('.')[-1]) > 1 else 0,
        "DomainInPaths": 1 if parsed_url.netloc.split('.')[-2] in parsed_url.path else 0,
        # Verificar si el dominio está en la ruta
        # "HttpsInHostname": 1 if 'https' in parsed_url.netloc else 0,
        # "HostnameLength": len(parsed_url.netloc),
        "PathLength": len(parsed_url.path),  # Longitud de la ruta
        "QueryLength": len(parsed_url.query),  # Longitud de la consulta
        # "DoubleSlashInPath": 1 if '//' in parsed_url.path else 0,
        # Hasta aca esta bien
        "NumSensitiveWords": obtener_numero_de_palabras_sensibles(url_to_extract),
        "EmbeddedBrandName": obtener_nombre_de_marca_incrustado(url_to_extract),
        "PctExtHyperlinks": calculate_pct_ext_hyperlinks(url_to_extract),  #
        "PctExtResourceUrls": 0.0,  #
        "ExtFavicon": 0,  #
        "InsecureForms": 0,  #
        "RelativeFormAction": 0,  #
        "ExtFormAction": 0,  #
        "AbnormalFormAction": 0,  #
        "PctNullSelfRedirectHyperlinks": 0.0,
        # Agregar función para calcular porcentaje de hipervínculos de auto-redirección nulos
        "FrequentDomainNameMismatch": 0,
        # Agregar función para detectar discrepancias frecuentes en el nombre de dominio
        # "FakeLinkInStatusBar": 0,  # Agregar función para detectar enlaces falsos en la barra de estado
        # "RightClickDisabled": 0,  # Agregar función para detectar clic derecho deshabilitado
        # "PopUpWindow": 0,  # Agregar función para detectar ventanas emergentes
        "SubmitInfoToEmail": 0,  #
        "IframeOrFrame": 0,  #
        "MissingTitle": 0,  #
        "ImagesOnlyInForm": 0,  #
        # "SubdomainLevelRT": 0,  # Agregar función temporal relacionada con el nivel del subdominio
        # "UrlLengthRT": 0,  # Agregar función temporal relacionada con la longitud de la URL
        # "PctExtResourceUrlsRT": 0.0,
        # Agregar función temporal relacionada con el porcentaje de URL de recursos externos
        # "AbnormalExtFormActionR": 0,
        # Agregar función temporal relacionada con acciones de formulario externas anormales
        "ExtMetaScriptLinkRT": 0,  #
        "PctExtNullSelfRedirectHyperlinksRT": 0.0
        # Agregar función temporal relacionada con el porcentaje de hipervínculos de auto-redirección nulos
    }
    return url_features


# Función para predecir si la URL es maliciosa


def predict_malicious(url, model):
    # Extraer características de la URL
    url_features = extract_features(url)
    # Realizar la predicción
    prediction = model.predict(url_features)
    # Obtener la probabilidad de la clase positiva
    probability = model.predict_proba(url_features)[:, 1][0]
    return prediction[0], probability


def get_url_content(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.content.decode('utf-8', errors='ignore')
        else:
            print("Error al obtener el contenido de la URL. Código de estado:", response.status_code)
            return None
    except Exception as e:
        print("Error al obtener el contenido de la URL:", e)
        return None


# Cargar el modelo entrenado

model = joblib.load("content/url-model.pkl")
# URL de ejemplo

url = "thewhiskeydregs.com/wp-content/themes/widescreen/includes/temp/promocoessmiles/?84784787824HDJNDJDSJSHD//2724782784/"
print(f"{GREEN}URL de ejemplo: {RESET}{url}")
url_features = extract_features(url)
print("---Estos son los valores de la URL con nuestros algoritmos---")
for key, value in url_features.items():
    print(key, ":", value)

html_content = get_url_content(url)


# Predecir si la URL es maliciosa
# prediction, probability = predict_malicious(url, model)
# print("Predicción:", prediction)

# Completar y verificar estas funciones

# print("Probabilidad de ser maliciosa:", probability)


def calcular_porcentaje_null_self_redirect(html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        num_links = len(soup.find_all('a'))
        num_null_self_redirect_links = len([link for link in soup.find_all('a') if link.get('href') == url])
        pct_null_self_redirect = (num_null_self_redirect_links / num_links) * 100
        return pct_null_self_redirect
    except Exception as e:
        print("Error al calcular el porcentaje de hipervínculos de auto-redirección nulos:", e)
        return None


def analizar_scripts_meta(html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        num_scripts = len(soup.find_all('script', src=True))
        num_meta_links = len(soup.find_all('meta', content=True))
        return num_scripts, num_meta_links
    except Exception as e:
        print("Error al analizar scripts y enlaces meta:", e)
        return None, None


def obtener_numero_de_scripts_externos_y_enlaces_meta(html_content):
    num_scripts = len(re.findall(r'<script\s[^>]*src\s*=\s*[\"\']([^\"\']*)[\"\'][^>]*>', html_content))
    num_meta_links = len(re.findall(r'<meta\s[^>]*content\s*=\s*[\"\']([^\"\']*)[\"\'][^>]*>', html_content))
    return num_scripts, num_meta_links


if html_content:
    num_scripts, num_meta_links = obtener_numero_de_scripts_externos_y_enlaces_meta(html_content)
    print("Número de scripts externos:", num_scripts)
    print("Número de enlaces meta:", num_meta_links)
else:
    print("No se pudo obtener el contenido HTML de la URL:", url)
