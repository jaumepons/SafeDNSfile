# SafeDNSfile: Servicio Anti-Pharming para blacklist DNS externas
# Version: 0.1
#
# Instrucciones:
# 1. Configurar nombre de host y puerto de escucha del servidor web.
# 2. Por defecto, se buscarán todas las IP's entre 0.0.0.0 a 255.255.255.255 y se modificarán por 127.0.0.1
# 3. Arrancar script en Python3 (python3 safeDNSfile.py &).
#    Lo ideal es ejecutarlo en boot o enviarlo a background (ej: "nohup python3 safeDNSfile.py &"
# 4. Añadir en Pi-Hole, AdGuard o el sistema que se utilice la URL externa con el prefijo del servidor SafeDNSfile
#    Ejemplo: http://localhost:8080/http://www.malwaredomainlist.com/hostslist/hosts.txt
#
# CONFIGURACIÓN
hostName = "localhost"
serverPort = 8080
cambiarIP = "127.0.0.1"
# FIN CONFIGURACIÓN




from http.server import BaseHTTPRequestHandler, HTTPServer
import requests, re, datetime

class ServidorWeb(BaseHTTPRequestHandler):
    def do_GET(self):
        
        url = self.path[1:]

        if re.match('^(http:\/\/|https:\/\/)[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$', url):
            urlContenido = requests.get(url)
            safeDNS = re.sub('(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}[\s\t]', cambiarIP + "\t", urlContenido.text)

            self.send_response(urlContenido.status_code)
            self.send_header("Content-type", urlContenido.headers['content-type'])
            self.end_headers()
            self.wfile.write(bytes(safeDNS + "\r", "utf-8"))
            now = datetime.datetime.now()
            self.wfile.write(bytes("\r# SafeDNSfile: Change all IP's to: " + cambiarIP, "utf-8"))
            self.wfile.write(bytes("\r# SafeDNSfile: " + now.strftime("%Y-%m-%d %H:%M:%S"), "utf-8"))
            
            
if __name__ == "__main__":        
    webServer = HTTPServer((hostName, serverPort), ServidorWeb)
    print("SafeDNSfile iniciado en http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Servidor parado.")
