import streamlit as st
import pandas as pd
import joblib
import time
import matplotlib.pyplot as plt
import seaborn as sns
from UrlValidator import UrlValidator

# Configurar la página
st.set_page_config(page_title="URL Phishing Analyzer", page_icon=":shield:", layout="wide")

# Variable PCT
pct_phishing = 0

# Cargar el modelo
rf_classifier = joblib.load("url-model.pkl")

# Define a custom color palette
custom_palette = [
    "#005BFF", "#FF6347", "#32CD32", "#FFD700",
    "#4B0082", "#FF4500", "#8A2BE2", "#00CED1", "#FF1493"
]


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

    return url_df


# Función para crear gráficos
def plot_feature_analysis(data):
    columns = st.columns(4)
    column_index = 0

    # Graficar los valores de cada columna
    for column in data.columns:
        fig, ax = plt.subplots(figsize=(5, 3))

        # Establecer fondo oscuro
        fig.patch.set_facecolor("#1A1A1A")  # Fondo del gráfico
        ax.set_facecolor("#1A1A1A")  # Fondo de los ejes

        # Cambiar el color de las etiquetas y títulos
        ax.tick_params(colors='white', which='both')  # Cambiar el color de los ticks
        ax.xaxis.label.set_color('white')  # Cambiar el color de la etiqueta x
        ax.yaxis.label.set_color('white')  # Cambiar el color de la etiqueta y
        ax.title.set_color('white')  # Cambiar el color del título

        # Configurar la paleta personalizada
        sns.set_palette(custom_palette)

        # Crear el gráfico de barras
        barplot = sns.barplot(x=data[column].index, y=data[column].values, ax=ax, palette=custom_palette)

        plt.title(f'Análisis de {column}')
        plt.ylabel('Valor')

        # Agregar etiquetas a las barras
        for p in barplot.patches:
            barplot.annotate(format(p.get_height(), '.2f'),
                             (p.get_x() + p.get_width() / 2., p.get_height()),
                             ha='center', va='center',
                             xytext=(0, 10),
                             textcoords='offset points',
                             color='white')  # Etiquetas de las barras en blanco

        # Ajustar la altura del gráfico
        plt.ylim(0, data[column].max() * 1.2)

        # Mostrar la gráfica en la columna correspondiente
        columns[column_index].pyplot(fig)
        column_index = (column_index + 1) % 4


# Columnas centradas para el título y la entrada de URL
centered_columns = st.columns([1, 2, 1])

with centered_columns[1]:
    # Titles
    st.markdown(" # URL Phishing Analyzer")
    st.markdown(" A Machine Learning application made by ***Thomas Sorza*** and ***Santiago Orjuela***. ")

    # Input field and button in a single row
    url_input_col, button_col = st.columns([3, 1])
    url_input = url_input_col.text_input("Ingrese la URL para analizar:", placeholder="Presione Enter para aplicar")
    analyze_button = button_col.button("Analizar")

    if analyze_button and len(url_input) >= 10:
        url_df = execute_alg(url_input)
        print(url_df)

        # Progress Bar
        progress_bar = st.progress(0)
        for perc_completed in range(100):
            time.sleep(0.03)
            progress_bar.progress(perc_completed + 1)

        # Expandable section
        with st.expander(" ¡Su resultado está listo! "):
            st.write(get_text_result(), unsafe_allow_html=True)
    else:
        st.error("La URL debe tener al menos 10 caracteres.")

if analyze_button and len(url_input) >= 10:
    with st.expander(" ¡Análisis de características de la URL! "):
        plot_feature_analysis(url_df)

    pct_phishing = 0


# Definir change_result_state para evitar errores
def change_result_state():
    pass
