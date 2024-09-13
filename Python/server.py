# Library
# Author Alexander Onofrei
# Creation date: 13-09-2024

import http.server
import ssl

certificate_path = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Ressources/certificates_keys/server.crt"
keyfile_path = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Ressources/certificates_keys/server.key"

def start_HTTPS_server():
    httpd = http.server.HTTPServer(('localhost', 8443),http.server.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket,certfile=certificate_path,
                                   keyfile=keyfile_path, server_side=True, ssl_version=ssl.PROTOCOL_TLS)
    httpd.serve_forever()

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    start_HTTPS_server()

