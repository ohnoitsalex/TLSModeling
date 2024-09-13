# Library
# Author Alexander Onofrei
# Creation date: 13-09-2024

import requests

def sendGetRequest():
    res = requests.get('https://localhost:8443', verify=False)
    print(res)

if __name__ == '__main__':
    sendGetRequest()