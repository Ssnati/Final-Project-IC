import streamlit as st
from streamlit_shap import st_shap
import shap
import time
import joblib
import pandas as pd
import random  # Importar la librería random si es necesario
from UrlValidator import *

# Variable PCT
pct_phishing = 0

# Cargar el modelo
rf_classifier = joblib.load("url-model.pkl")

def available(display=0):
    return display

def get_text_result():
    if pct_phishing >= 50:
        return f"<span style='color:red'>Su URL ingresada es un {pct_phishing}% riesgosa de usar.</span>"
    else:
        return f"<span style='color:green'>Su URL ingresada es un {100 - pct_phishing}% segura de usar.</span>"

def execute_alg(url):
    global pct_phishing
    # Crear una instancia de UrlValidator y comprobar la URL
    url_validator = UrlValidator(url)
    url_validator.comprobar()
    
    # Obtener los parámetros como un diccionario
    url_params = url_validator.get_parameters_dict()
    
    # Crear un DataFrame con los parámetros
    url_df = pd.DataFrame([url_params])
    
    # Realizar la predicción
    prediction = rf_classifier.predict(url_df)
    pct_phishing = 100 if prediction[0] == 1 else 0

# Titles
st.markdown(" # URL Phishing Analyzer")
st.markdown(" A Machine Learning application made by ***Thomas Sorza*** and ***Santiago Orjuela***. ")

# Input field and button in a single row
url_input_col, button_col = st.columns([3, 1])
url_input = url_input_col.text_input("Ingrese la URL para analizar:", placeholder="Presione Enter para aplicar")
analyze_button = button_col.button("Analizar")

if analyze_button and len(url_input) >= 10:
    execute_alg(url_input)
    
    # Progress Bar
    progress_bar = st.progress(0)
    for perc_completed in range(100):
        time.sleep(0.03)
        progress_bar.progress(perc_completed + 1)

    # Expandable section
    with st.expander(" ¡Su resultado está listo! "):
        st.write(get_text_result(), unsafe_allow_html=True)
        pct_phishing = 0

else:
    st.error("La URL debe tener al menos 10 caracteres.")

# Definir change_result_state para evitar errores
def change_result_state():
    pass
