import joblib
import pandas as pd
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests
import time
from UrlValidator import *

# Clase UrlValidator
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
        self.url = url
        self.parameters = []
        self.url_parsed = urlparse(url)
        self.html_content = ""

    def clean(self):
        self.parameters = []

    def get_parameters_dict(self):
        return dict(zip(self.PARAM_NAMES, self.parameters))

    def comprobar(self):
        self.url = self.__url_comprobider()
        self.url_parsed = urlparse(self.url)
        self.html_content = self.__get_html_content(self.url)
        self.parameters = [
            self.url.count('.'),
            len(self.url_parsed.path.split('/')),
            len(self.url),
            self.url.count('-'),
            len(self.url_parsed.query),
            self.url.count('&'),
            self.__get_num_numeric_chars(),
            self.url_parsed.hostname.count('-'),
            len(self.url_parsed.path),
            len(self.url_parsed.query),
            self.__get_subdomain_level(),
            self.__get_num_sensitive_words(),
            self.__get_pct_ext_hyper_links(),
            self.__get_pct_ext_resource_urls(),
            self.__get_ext_favicon(),
            self.__get_insecure_forms(),
            self.__get_pct_null_self_redirect_hyperlinks(),
            self.__get_frequent_domain_name_mismatch(),
            self.__get_submit_info_to_email(),
            self.__get_iframe_or_frame(),
            self.__get_ext_meta_script_link_rt(),
            self.__get_pct_ext_null_self_redirect_hyperlinks_rt()
        ]

    def __get_html_content(self, url):
        try:
            response = requests.get(url)
            return response.content if response.status_code == 200 else str(response.status_code)
        except Exception as e:
            print("Error al obtener el contenido de la URL:", e)
            return "Error-URL"

    def __get_num_numeric_chars(self):
        return sum(c.isdigit() for c in self.url)

    def __get_subdomain_level(self):
        level = len(self.url_parsed.hostname.split('.'))
        if self.url_parsed.hostname.startswith('www.'):
            level -= 1
        if any(self.url_parsed.hostname.endswith(ext) for ext in self.DOMAIN_EXTENSIONS):
            level -= 1
        return level

    def __get_num_sensitive_words(self):
        return sum(word in self.url for word in self.SENSITIVE_WORDS)

    def __get_pct_ext_hyper_links(self):
        domain = self.url_parsed.netloc
        soup = BeautifulSoup(self.html_content, 'html.parser')
        all_links = soup.find_all('a', href=True)
        total_links = len(all_links)
        ext_links = sum(1 for link in all_links if urlparse(link['href']).netloc != domain)
        return ext_links / total_links if total_links > 0 else 0

    def __get_pct_ext_resource_urls(self):
        domain = self.url_parsed.netloc
        soup = BeautifulSoup(self.html_content, 'html.parser')
        resources = soup.find_all(['script', 'img', 'link'], src=True) + soup.find_all('link', href=True)
        total_resources = len(resources)
        ext_resources = sum(1 for res in resources if urlparse(res.get('src', res.get('href'))).netloc != domain)
        return ext_resources / total_resources if total_resources > 0 else 0

    def __get_ext_favicon(self):
        domain = self.url_parsed.netloc
        soup = BeautifulSoup(self.html_content, 'html.parser')
        favicons = soup.find_all('link', rel='icon')
        return 1 if any(urlparse(favicon['href']).netloc != domain for favicon in favicons) else 0

    def __get_insecure_forms(self):
        soup = BeautifulSoup(self.html_content, 'html.parser')
        forms = soup.find_all('form', action=True)
        return 1 if any('https' not in form['action'] for form in forms) else 0

    def __get_pct_null_self_redirect_hyperlinks(self):
        soup = BeautifulSoup(self.html_content, 'html.parser')
        links = soup.find_all('a', href=True)
        total_links = len(links)
        null_self_redirects = sum(1 for link in links if link['href'] == self.url)
        return null_self_redirects / total_links if total_links > 0 else 0

    def __get_frequent_domain_name_mismatch(self):
        domain = self.url_parsed.netloc
        soup = BeautifulSoup(self.html_content, 'html.parser')
        elements = soup.find_all(['a', 'form'], action=True)
        return 1 if any(urlparse(element['action']).netloc != domain for element in elements) else 0

    def __get_submit_info_to_email(self):
        soup = BeautifulSoup(self.html_content, 'html.parser')
        return 1 if any('mailto:' in element['action'] for element in soup.find_all(['a', 'form'], action=True)) else 0

    def __get_iframe_or_frame(self):
        soup = BeautifulSoup(self.html_content, 'html.parser')
        return 1 if soup.find_all(['iframe', 'frame']) else 0

    def __get_ext_meta_script_link_rt(self):
        try:
            html_content1 = self.html_content
            time.sleep(5)
            html_content2 = self.__get_html_content(self.url)
            if html_content1 and html_content2:
                return 1 if self.__analize_scripts_meta(html_content1) or self.__analize_scripts_meta(html_content2) else 0
            else:
                return -1
        except Exception as e:
            print("Error en obtener_ext_meta_script_link_rt:", e)
            return -1

    def __analize_scripts_meta(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = soup.find_all('script', src=True)
        metas = soup.find_all('meta', content=True)
        return 1 if scripts or metas else 0

    def __get_pct_ext_null_self_redirect_hyperlinks_rt(self):
        soup = BeautifulSoup(self.html_content, 'html.parser')
        links = soup.find_all('a', href=True)
        total_links = len(links)
        null_self_redirects = sum(1 for link in links if link['href'] == self.url)
        return 1 if null_self_redirects > 0 else 0

    def __url_comprobider(self):
        if self.url.startswith('http://') or self.url.startswith('https://'):
            return self.url
        else:
            return 'http://' + self.url