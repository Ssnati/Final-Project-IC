import time
from urllib.parse import urlparse

import pandas as pd
import requests
from bs4 import BeautifulSoup


class UrlValidator:
    DOMAIN_EXTENSIONS = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.int', '.arpa', '.co', '.info', '.biz', '.it',
                         '.io', '.ai', '.ly', '.gl', '.tv', '.me', '.us', '.uk', '.ca', '.au', '.fr', '.de', '.es']
    SENSITIVE_WORDS = ['phishing', 'password', 'login', 'bank', 'paypal']
    PARAM_NAMES = ["NumDots", "PathLevel", "UrlLength", "NumDash", "NumQueryComponents", "NumAmpersand",
                   "NumNumericChars", "NumDashInHostname", "PathLength", "QueryLength", "SubdomainLevel",
                   "NumSensitiveWords", "PctExtHyperlinks", "PctExtResourceUrls", "ExtFavicon", "InsecureForms",
                   "PctNullSelfRedirectHyperlinks", "FrequentDomainNameMismatch", "SubmitInfoToEmail",
                   "IframeOrFrame", "ExtMetaScriptLinkRT", "PctExtNullSelfRedirectHyperlinksRT"]

    def __init__(self, url):
        self.__url = url
        self.__parameters = []
        self.__url_parsed = urlparse(url)
        self.__html_content = ""

    def comprobar(self):
        self.__url = self.__url_comprobider()
        self.__url_parsed = urlparse(self.__url)
        self.__html_content = self.__get_html_content(self.__url)
        # """
        # "NumDots": url_to_extract.count('.'),
        # "PathLevel": len(parsed_url.path.split('/')),
        # "UrlLength": len(url_to_extract),
        # "NumDash": url_to_extract.count('-'),
        # "NumQueryComponents": len(parse_qs(parsed_url.query)),
        # "NumAmpersand": url_to_extract.count('&'),
        # "NumNumericChars": sum(c.isdigit() for c in url_to_extract),
        # "NumDashInHostname":0,
        # "PathLength": len(parsed_url.path),  # Longitud de la ruta
        # "QueryLength": len(parsed_url.query),  # Longitud de la consulta
        # "SubdomainLevel": 0,
        # "NumSensitiveWords": obtener_numero_de_palabras_sensibles(url_to_extract),
        # "PctExtHyperlinks": calculate_pct_ext_hyperlinks(url_to_extract),  #
        # "PctExtResourceUrls": 0.0,  #
        # "ExtFavicon": 0,  #
        # "InsecureForms": 0,  #
        # "PctNullSelfRedirectHyperlinks": 0.0,
        # "FrequentDomainNameMismatch": 0,
        # "PopUpWindow": 0,
        # "SubmitInfoToEmail": 0,  #
        # "IframeOrFrame": 0,  #
        # "ExtMetaScriptLinkRT": 0,  #
        # "PctExtNullSelfRedirectHyperlinksRT": 0.0
        # """
        self.__parameters.append(self.__url.count('.'))
        self.__parameters.append(len(self.__url_parsed.path.split('/')))
        self.__parameters.append(len(self.__url))
        self.__parameters.append(self.__url.count('-'))
        self.__parameters.append(len(self.__url_parsed.query))
        self.__parameters.append(self.__url.count('&'))
        self.__parameters.append(self.__get_num_numeric_chars())
        self.__parameters.append(self.__url_parsed.hostname.count('-'))
        self.__parameters.append(len(self.__url_parsed.path))
        self.__parameters.append(len(self.__url_parsed.query))
        self.__parameters.append(self.__get_subdomain_level())
        self.__parameters.append(self.__get_num_sensitive_words())
        self.__parameters.append(self.__get_pct_ext_hyper_links())
        self.__parameters.append(self.__get_pct_ext_resource_urls())
        self.__parameters.append(self.__get_ext_favicon())
        self.__parameters.append(self.__get_insecure_forms())
        # Verificados
        self.__parameters.append(self.__get_pct_null_self_redirect_hyperlinks())
        self.__parameters.append(self.__get_frequent_domain_name_mismatch())
        self.__parameters.append(self.__get_submit_info_to_email())
        self.__parameters.append(self.__get_iframe_or_frame())
        #null test
        self.__parameters.append(self.__get_ext_meta_script_link_rt())
        self.__parameters.append(self.__get_pct_ext_null_self_redirect_hyperlinks_rt())

    def __get_html_content(self, url):
        try:
            response = requests.get(url)
            return response.content if response.status_code == 200 else str(response.status_code)
        except Exception as e:
            print("Error al obtener el contenido de la URL:", e)
            return "Error-URL"  # Verificar si se debe retornar un string vacio o un valor nulo cuando no se puede obtener el contenido

    def __get_num_numeric_chars(self):
        total = 0
        for c in self.__url:
            if c.isdigit():
                total += 1
        return total

    def __get_subdomain_level(self):
        level = len(self.__url_parsed.hostname.split('.'))
        if self.__url_parsed.hostname.startswith('www.'):
            level -= 1
        if any(self.__url_parsed.hostname.endswith(domain_extension) for domain_extension in self.DOMAIN_EXTENSIONS):
            level -= 1
        return level

    def __get_num_sensitive_words(self):
        total = 0
        for word in self.SENSITIVE_WORDS:
            if word in self.__url:
                total += 1
        return total

    """
        "PctExtHyperlinks": [0.0-1.0]
        "PctExtResourceUrls": [0.0-1.0]
        "ExtFavicon": [0,1]
        "InsecureForms": [0,1]
        "PctNullSelfRedirectHyperlinks": [0.0-1.0]
        "FrequentDomainNameMismatch": [0,1]
        "SubmitInfoToEmail": [0,1]
        "IframeOrFrame": [0,1]
        "ExtMetaScriptLinkRT": [1,-1,0]
        "PctExtNullSelfRedirectHyperlinksRT": [1,-1,0]
    """

    def __get_pct_ext_hyper_links(self):
        domain = self.__url_parsed.netloc
        soup = BeautifulSoup(self.__html_content, 'html.parser')
        all_links = soup.find_all('a', href=True)
        total_links = len(all_links)
        ext_links = 0
        for link in all_links:
            link_domain = urlparse(link['href']).netloc
            if link_domain != domain:
                ext_links += 1
        return ext_links / total_links if total_links > 0 else 0

    def __get_pct_ext_resource_urls(self):

          # Extraer el dominio del URL
        domain = self.__url_parsed.netloc

        # Parsear el contenido HTML con BeautifulSoup
        soup = BeautifulSoup(self.__html_content, 'html.parser')
        # Encontrar todas las etiquetas de recursos relevantes
        script_resources = soup.find_all('script', src=True)
        img_resources = soup.find_all('img', src=True)
        link_resources = soup.find_all('link', href=True)
        # Combinar todas las etiquetas en una lista
        resources = script_resources + img_resources + link_resources
        total_resources = len(resources)
        ext_resources = 0
        for res in resources:
            if res.name == 'link':
                resource_url = res['href']
            else:
                resource_url = res['src']
            if urlparse(resource_url).netloc != domain:
                ext_resources += 1

        # Calcular y devolver el porcentaje de recursos externos
        return ext_resources / total_resources if total_resources > 0 else 0

    def __get_ext_favicon(self):
        domain = self.__url_parsed.netloc
        soup = BeautifulSoup(self.__html_content, 'html.parser')
        favicons = soup.find_all('link', rel='icon')
        result = any(urlparse(favicon['href']).netloc != domain for favicon in favicons)
        return 1 if result else 0

    def add_parameters(self):
        self.__parameters.append(self.__get_ext_favicon())

    def __get_insecure_forms(self):
        soup = BeautifulSoup(self.__html_content, 'html.parser')
        forms = soup.find_all('form', action=True)
        result = any('https' not in form['action'] for form in forms)
        return 1 if result else 0

    def __get_pct_null_self_redirect_hyperlinks(self):
        soup = BeautifulSoup(self.__html_content, 'html.parser')
        links = soup.find_all('a', href=True)
        total_links = len(links)
        null_self_redirects = sum(1 for link in links if link['href'] == self.__url)
        return null_self_redirects / total_links if total_links > 0 else 0

    def __get_frequent_domain_name_mismatch(self):
        domain = self.__url_parsed.netloc
        soup = BeautifulSoup(self.__html_content, 'html.parser')
        elements = soup.find_all(['a', 'form'], action=True)
        result = any(urlparse(element['action']).netloc != domain for element in elements)
        return 1 if result else 0

    def __get_submit_info_to_email(self):
        soup = BeautifulSoup(self.__html_content, 'html.parser')
        result = any('mailto:' in element['action'] for element in soup.find_all(['a', 'form'], action=True))
        return 1 if result else 0

    def __get_iframe_or_frame(self):
        soup = BeautifulSoup(self.__html_content, 'html.parser')
        iframes = soup.find_all('iframe')
        frames = soup.find_all('frame')
        result = len(iframes) > 0 or len(frames) > 0
        return 1 if result else 0

    def __get_ext_meta_script_link_rt(self):
        try:
            html_content1 = self.__html_content
            time.sleep(5)  # Esperar 5 segundos antes de hacer otra solicitud
            html_content2 = self.__get_html_content(self.__url)
            if html_content1 and html_content2:
                result1 = self.__analize_scripts_meta(html_content1)
                result2 = self.__analize_scripts_meta(html_content2)
                return 1 if result1 or result2 else 0
            else:
                return -1
        except Exception as e:
            print("Error en obtener_ext_meta_script_link_rt:", e)
            return -1

    def __analize_scripts_meta(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = soup.find_all('script', src=True)
        metas = soup.find_all('meta', content=True)
        return 1 if len(scripts) > 0 or len(metas) > 0 else 0

    def __get_pct_ext_null_self_redirect_hyperlinks_rt(self):
        soup = BeautifulSoup(self.__html_content, 'html.parser')
        links = soup.find_all('a', href=True)
        total_links = len(links)
        null_self_redirects = sum(1 for link in links if link['href'] == self.__url)
        return 1 if null_self_redirects > 0 else 0

    @property
    def url(self):
        return self.__url

    @property
    def parameters(self):
        return self.__parameters

    @property
    def url_parsed(self):
        return self.__url_parsed

    @url.setter
    def url(self, url):
        self.__url = url

    @parameters.setter
    def parameters(self, parameters):
        self.__parameters = parameters

    @url_parsed.setter
    def url_parsed(self, url_parsed):
        self.__url_parsed = url_parsed

    def __url_comprobider(self):
        if self.__url.startswith('http://') or self.__url.startswith('https://'):
            return self.__url
        else:
            return 'http://' + self.__url


if __name__ == '__main__':
    # Prueba de la clase UrlValidator con las url en 'phishing_site_urls_test.csv'
    test_urls = pd.read_csv("../phishing_site_urls_test.csv")
    count = 0
    while count < 10:
        url = test_urls["URL"][count]
        url_validator = UrlValidator(url)
        url_validator.comprobar()
        print(f"URL {count + 1}: {url}")
        for i in range(len(url_validator.parameters)):
            print(f"{url_validator.PARAM_NAMES[i]}: {url_validator.parameters[i]}")
        print("\n")
        count += 1
