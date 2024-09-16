# Library
# Author Alexander Onofrei
# Creation date: 13-09-2024

from OpenSSL import SSL
import requests
import urllib3

# Suppress the warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def sendGetRequest():

    response = requests.get('https://localhost:8443', verify=False)

    print("Response in text by server: ", response.text)

if __name__ == '__main__':
    sendGetRequest()