import re
import nvdlib
import sys
import socket
import pyfiglet
from datetime import datetime
import os
import nmap
from pathlib import Path

location = "{}\\Desktop\\".format(Path.home())
file = "scan"
extension = ".log"

os.system('color a')
nm = nmap.PortScanner()

open_ports = []
# Generar excepciones a errores en la busqueda de vulners --
# Puede estar bien el que todo el escaneo se vaya guardado en un archivo que creemos.


def check_start():
    # Defining a target
    try:
        if sys.argv[1]:
            # change hostname to IPv4

            if re.findall("[.]", sys.argv[1]) == [".", ".", "."]:
                veryfy = sys.argv[1].split(".")
                for num in veryfy:
                    if int(num) > 255:
                        print("\nDirección IPv4 inválida.\n")
                        exit()

            try:
                target = socket.gethostbyname(sys.argv[1])
                graph(target)
            except socket.gaierror:
                print('Direccion IPv4 inválida')
                exit()
    except IndexError:
        print("""
 ║
 ╠══════► Obligatorio --> Direccion IP / Puertos a analizar.  
 ║
 ╠══════► Tipología   --> <name_script> <ip_address>  
 ║  
 ╚══════► EJEMPLO 	  --> port_scaner.py 127.0.0.1 """)

        exit()


def num_ports():
    global ports
    while True:
        ports = input('\nIntroduce la cantidad de puertos a escanear - (500 - Primeros 500): ')

        if ports == '--help':
            os.system('cls')
            print("""---- Usabilidad "PORT SCANNER" v0.2 ----
Esta herramienta está pensada para ser muy facil de utilizar.    
Solamente se tiene que escribir el nº máximo de puertos. (500 -- Los primeros 500 Puertos)
 
   1. Se ejecuta un escaneo de puertos para localizar los abiertos

   2. Ejecutamos un analisis de servicios de dichos puertos abiertos, identificamos información sobre 
     los servicios encontrados sin confirmacion PING ya que se ha mirado anteriormente

   3. Iniciamos una busqueda de vulnerabilidades públicas en dichos servicios...""")
        else:
            try:
                ports = int(ports)
                if ports > 65535:
                    input('Has superado el número máximo de puertos.\n'
                          'Se reducirá a "65535" (numero máx. de puertos) -- [ENTER]')
                    ports = 65535
                break
            except ValueError:
                print("Arguemnto inválido.\nPara obtener ayuda escriba --> '--help'")


def banner():
    print("""\n
╔═══════╗                                            			        ╔═══════╗
║       ║                                                                       ║       ║
║     ╔═══════════════════════════════════════════════════════════════════════════╗     ║
╚═════║  						                          ║═════╝
      ║   ____   ___  ____ _____   ____   ____    _    _   _ _   _ _____ ____  ©  ║
      ║  |  _ \ / _ \|  _ \_   _| / ___| / ___|  / \  | \ | | \ | | ____|  _ \    ║
      ║  | |_) | | | | |_) || |   \___ \| |     / _ \ |  \| |  \| |  _| | |_) |   ║
      ║  |  __/| |_| |  _ < | |    ___) | |___ / ___ \| |\  | |\  | |___|  _ <    ║
      ║  |_|    \___/|_| \_\|_|   |____/ \____/_/   \_\_| \_|_| \_|_____|_| \_\   ║
      ║								                  ║
      ║                                                             v0.3.1        ║
      ╚═══════════════════════════════════════════════════════════════════════════╝                                                                          

              [INFO] Herramienta para analizar puertos de una dirección IP              
                 ║                                                 ║                                                                                             
                 ║                                                 ║
                 ╚══════► Escriba --help para obtener ayuda ◄══════╝
                    \n""")


def init(now, target):
    print("-" * 55)
    print("Objetivo --> {} <--> Nº ports {}".format(target, ports))
    print("Analisis iniciado --> {}".format(now))
    print("-" * 55)


def graph(target):
    os.system('cls')
    banner()
    num_ports()
    os.system('cls')
    banner()
    # Banner
    scan(target)


def scan(target):
    try:
        now = str(datetime.now())
        init(now, target)
        for port in range(1, ports):
            print("\r" + 'Analizando Puerto : %s/%s [%s%s] %.2f%%' % (port, ports, "▓"*int(port*25/ports),
                                                                      "▒"*(25-int(port*25/ports)),
                                                                      float(port/ports*100)), end="")
            # Creamos el Socket para la conexión
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Definimos tiempo máximo de espera a la conexion
            socket.setdefaulttimeout(0.5)
            # creamos la conexion
            result = s.connect_ex((target, port))
            # Si resulta victorioisa la conexion informamos de puerto abierto
            if result == 0:
                open_ports.append(port)
                os.system('cls')
                banner()
                init(now, target)
                for open_port in open_ports:
                    print("[♦] - El puerto {} esta abierto.".format(open_port))
                    print("-"*50)
            s.close()

        check_serv(target)
    # Creamos la salida del programa
    except socket.gaierror:
        print("\nNo se ha encontrado el HOST")
        sys.exit()
    except socket.error:
        print("\nEl Servidor no responde")
        sys.exit()


def check_serv(target):
    # Creamos lista ordenada de puertos para el scaner
    p_str = [str(a) for a in open_ports]
    p_str = (",".join(p_str))
    print("\n\nLos puertos abiertos son: {}".format(open_ports))

    # Preguntamos si quiere analisis de versiones de servicio
    serv = input("[♦] ¿Quieres ejecutar un analisis de versiones a los puertos abiertos? [S/n] --> ")
    if serv in ["S", 's']:
        ascii_part = pyfiglet.figlet_format("Service  SCAN")
        print(ascii_part)

        print("""Escaneando versiones de servicio...) 
        ╚══════► Esto puede tardar un poco, espere.""")

        nm.scan(target, arguments="-p {} -sS -sV -sC".format(p_str,))
        dict_serv = {}
        for p in open_ports:
            print("Analisis puerto nº{} \n".format(p))
            state = nm[target]['tcp'][int(p)]['state']
            name = nm[target]['tcp'][int(p)]['name']
            product = nm[target]['tcp'][int(p)]['product']
            version = nm[target]['tcp'][int(p)]['version']
            extrainfo = nm[target]['tcp'][int(p)]['extrainfo']
            cpe = nm[target]['tcp'][int(p)]['cpe']
            if product == "":
                dict_serv[p] = {
                    'name': name,
                    'version': version
                }
            else:
                dict_serv[p] = {
                    'name': product,
                    'version': version
                }

            try:
                script = [nm[target]['tcp'][int(p)]['script'][ind] for ind in nm[target]['tcp'][int(p)]['script']]
                if len(script) <= 1:

                    print(
                        "Puerto: {}/{} \n<--> Especificaciones del servicio <--> \n[♦] Nombre: {}  |   Producto: {}  "
                        "|  Versión: {}  |  {}  |  CPE: {}  \n\nInfo: \n{}  \n".format(
                            p, state, name, product, version, extrainfo, cpe, script[0]))
                    print("\n", "-" * 50, "\n")
                else:
                    print(
                        "Puerto: {}/{} \n<--> Información del servicio <--> \n[♦] Nombre: {}  |   Producto: {}  "
                        "|  Versión: {}  |  Extra info: {}  |  CPE: {}  \n\nInfo: \n{}\n{}  \n".format(
                            p, state, name, product, version, extrainfo, cpe, script[0], script[1]))
                    print("\n", "-" * 50, "\n")
            except KeyError:
                print(
                    "Puerto: {}/{} \n<--> Información del servicio <--> \n[♦] Nombre: {}  |   Producto: {}  "
                    "|  Versión: {}  |  Extra info: {}  |  CPE: {}  \n\n".format(
                        p, state, name, product, version, extrainfo, cpe))
                print("\n", "-" * 50, )

        vuln = input("[♦] ¿Quieres ejecutar un analisis de vulnerabilidades a los servicios analizados? [S/n]")
        if vuln in ['S', 's']:
            scan_vuln_services(target, p_str, dict_serv)
        else:
            save = input("¿Quieres guardar los resultados en un archivo?")
            exit()
    else:
        print("")
        exit()


def scan_vuln_services(target, p_str, dict_serv):
    ascii_part_2 = pyfiglet.figlet_format("Vulner SCAN")
    vulner = {}
    print(ascii_part_2)

    for prt in dict_serv:
        name = dict_serv[prt]['name']
        version = dict_serv[prt]['version']
        service = "{} {}".format(name, version)
        try:
            results = nvdlib.searchCVE(keywordSearch=service)[0]
            cve = results.id
            date = results.lastModified
            desc = results.descriptions[0].value
            dificulty = results.metrics.cvssMetricV2[0].cvssData.accessComplexity
            exploit_score = results.v2exploitability
            severity = results.v2severity
            access = results.metrics.cvssMetricV2[0].cvssData.accessVector
            url = results.references[12].url
            vulner[cve] = {"name": name,
                           "service": service}

            print("""\n
🅿:{} -- 🆂🅴🆁🆅🅸🅲🅴: {}
═════════════════════════════════════════►
[♦] CVE: {} 
-----------------------------------------
[♦] Date: {}              
-----------------------------------------
[♦] Dificulty: {} 
----------------------------------------
[♦] Severity: {}
----------------------------------------
[♦] Score: {}  
-----------------------------------------
[♦] How to acces: {}     
-----------------------------------------
[♦] Desciption: {}                        
-----------------------------------------                                     
[♦]URL: {}                              
═════════════════════════════════════════►""".format(prt, service, cve, date,
                                                     dificulty, severity,
                                                     exploit_score, access,
                                                     desc, url))

        except IndexError:
            print("No vulnerabildades detectadas en el servicio {}\n".format(service))

    save = input("¿Quieres guardar la informacion en un archivo? [S/n]")
    if save in ['S', 's']:
        with open(location + file + extension, "a") as log:
            log.write("")


def main():
    try:
        check_start()
    except KeyboardInterrupt:
        print("\n\nSaliendo del programa...")
        exit()


if __name__ == "__main__":
    main()
