import streamlit as st
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from tld import get_tld, is_tld
import re
from keras.models import load_model



def process_tld(url):
    try:
        res = get_tld(url, as_object = True, fail_silently=False,fix_protocol=True)
        pri_domain= res.parsed_url.netloc
    except :
        pri_domain= None
    return pri_domain

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def httpSecure(url):
    htp = urlparse(url).scheme
    match = str(htp)
    if match=='https':
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def Shortening_Service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
        '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters



model  = load_model(r"C:\Users\dalwa\Desktop\Streamlit URL detection\urlmodel.h5")

st.title('Paste the URL below to check whether it is malicious or not🔗')
url = st.text_input("Input URL😊", "") 

ok=st.button("Check if Malicious or not")

if ok:
     userInput= pd.DataFrame(
   {
      "url_len": [len(url)],
      "@": [url.count('@')],
      "?": [url.count('?')],
      "-": [url.count('-')],
      "=": [url.count('=')],
      ".": [url.count('.')],
      "#": [url.count('#')],
      "%": [url.count('%')],
      "+": [url.count('+')],
      "$": [url.count('$')],
      "!": [url.count('!')],
      "*": [url.count('*')],
      ",": [url.count(',')],
      "//": [url.count('//')],
      "abnormal_url": [abnormal_url(url)],
      "https": [httpSecure(url)],
      "digits": [digit_count(url)],
      "letters": [letter_count(url)],
      "Shortening_Service": [Shortening_Service(url)],
      "having_ip_address": [having_ip_address(url)]
    })

     prediction=model.predict(userInput)
     prediction_class=prediction.argmax(axis=-1)
     
     if(prediction_class[0]==0):
        st.success("This URL is safe! Go ahead and open it✔️")
     elif(prediction_class[0]==1):
        st.error("This URL is of defacement type. Don't open it❌")
     elif(prediction_class[0]==2):
        st.error("This URL is of phishing type. Don't open it❌")
     else:
        st.error("This URL is of malware type. Don't open it❌")
     st.write("Probabilty of the different types:")

     final_table=pd.DataFrame(prediction)
     final_table.columns=['benign','defacement','phishing','malware']
     st.dataframe(final_table)
     
     
     
    
