# Esta clase esta hecha para hacer una graficacion de los datos
import matplotlib.pyplot as plt
import pandas as pd

# Cargar los datos
data = pd.read_csv("content/Phishing_Legitimate_full.csv")

# Grafica para ver la distribución de las clases
plt.figure(figsize=(6, 4))
data["CLASS_LABEL"].value_counts().plot(kind="bar", color=["skyblue", "salmon"])
plt.xticks(ticks=[0, 1], labels=["Legítima", "Phishing"], rotation=0)
plt.xlabel("Clase")
plt.ylabel("Número de URLs")
plt.title("Distribución de clases")
plt.show()

# Cuantos datos hay en cada una de las variables (columnas)
print(data.info())
print(data["CLASS_LABEL"].value_counts())

# Quiero ver los valores que tiene cada columna, la cantidad de valores unicos en cada columna
print(data.nunique())

# Graficar cuales son los valores que tiene cada columna
for column in data.columns:
    print(data[column].value_counts())
    print("\n")

malicious_data = data[data["CLASS_LABEL"] == 1]
legitimate_data = data[data["CLASS_LABEL"] == 0]


# Grafico de barras (pequeño) para los valores de cada columna, para urls maliciosas y legítimas
def plot_column_values(column):
    plt.figure(figsize=(6, 4))
    malicious_data[column].value_counts().plot(kind="bar", color="salmon", alpha=0.7, label="Phishing")
    legitimate_data[column].value_counts().plot(kind="bar", color="skyblue", alpha=0.7, label="Legítima")
    plt.xlabel(column)
    plt.ylabel("Número de URLs")
    plt.title(f"Distribución de {column}")
    plt.legend()
    plt.show()


for column in data.columns:
    plot_column_values(column)
