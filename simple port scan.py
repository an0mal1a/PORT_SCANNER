import ctypes
from datetime import datetime
import re
import nvdlib
import socket
import pyfiglet
import sys
import io
import os
import nmap
from pathlib import Path
from pyExploitDb import PyExploitDb
import colorama
from colorama import Fore


# Continuar subetting
# Juntar info de nmap y de base de datos.


colorama.init()
location = "{}\\Desktop\\".format(Path.home())
file = "scan"
extension = ".log"

# os.system('color a')
nm = nmap.PortScanner()
open_ports = []


def print_log(log):
    with open(location + file + extension, "a") as file_log:
        file_log.write("\n")
        file_log.write(log)



def is_admin():
    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        print("ESTA HERRAMIENTA NECESITA PERMISOS DE ADMINISTRADOR / ROOT.")
        exit()


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
                funcions(target)
            except socket.gaierror:
                print('Direccion IPv4 inválida')
                exit()
    except IndexError:
        print(Fore.RED + """
 ║
 ╠══════► Obligatorio --> Direccion IP / Puertos a analizar.  
 ║
 ╠══════► Tipología   --> <name_script> <ip_address>  
 ║  
 ╚══════► EJEMPLO 	  --> port_scaner.py 127.0.0.1 """)
        exit()

    except ValueError:
        print('Debes introducir NUMEROS...')
        print(Fore.RED + """
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
        ports = input(Fore.YELLOW + '\nIntroduce la cantidad de puertos a escanear - (EJ: 500 - Primeros 500) --> ')
        if 'help' in ports:
            if os.name == "posix":
                os.system("clear")
            else:
                os.system("cls")
            banner()
            print(Fore.GREEN + """---- Usabilidad "PORT SCANNER" v0.3.8 ----
Esta herramienta está pensada para ser muy facil de utilizar.    
Solamente se tiene que escribir el nº máximo de puertos. (500 -- Los primeros 500 Puertos)

1. Se ejecuta un escaneo de puertos para localizar los abiertos

2. Ejecutamos un analisis de servicios de dichos puertos abiertos, identificamos información sobre 
los servicios encontrados 

3. Iniciamos una busqueda de vulnerabilidades públicas en dichos servicios...

4. Tenemos la opcion de buscar en la base de datos de ExploitDb algún exploit público.

5. Podemos abrir metasploit para utilziar la informacion recopilada anteriomente para lo que tengamos que hacer

Para ejecutar este script necesitamos de varios requisitos:
            - NMAP
            - Metasploit (opcional)""")
        else:
            try:
                ports = int(ports)
                if ports > 65535:
                    input('Has superado el número máximo de puertos.\n'
                          'Se reducirá a "65535" (numero máx. de puertos) -- [ENTER]')
                    ports = 65535
                break
            except ValueError:
                print(Fore.RED + "Arguemnto inválido.\nPara obtener ayuda escriba --> '--help'")


def banner():
    print(Fore.GREEN + """\n
  ╔═════════╗                                                 ╔═════════╗
  ║         ║                                                 ║         ║
  ║     ╔═════════════════════════════════════════════════════════╗     ║
  ╚═════║  				   		          ║═════╝                                    
        ║   ____   ___  ____ _____   ____   ____    _    _   _ ©  ║
        ║  |  _ \ / _ \|  _ \_   _| / ___| / ___|  / \  | \ | |   ║
        ║  | |_) | | | | |_) || |   \___ \| |     / _ \ |  \| |   ║
        ║  |  __/| |_| |  _ < | |    ___) | |___ / ___ \| |\  |   ║
        ║  |_|    \___/|_| \_\|_|   |____/ \____/_/   \_\_| \_|   ║
        ║							  ║                                   
        ║                                           v0.3.9        ║
        ╚═════════════════════════════════════════════════════════╝                                                                          

       [INFO] Herramienta para analizar puertos de una dirección IP 

             ║                                                 ║                                                                                             
             ║                                                 ║
             ╚══════► Escriba --help para obtener ayuda ◄══════╝
                    \n\n""")


def init(now, target):
    # Inicio del analisis, tiempo y objetivo
    print(Fore.YELLOW + "-" * 55)
    print(Fore.YELLOW + "Objetivo --> {} <--> Nº ports {}".format(target, ports))
    print(Fore.YELLOW + "Analisis iniciado --> {}".format(now))
    print("-" * 55)


def graph(target):
    # Escaneo de puertos gráfico
    if os.name == "posix":
        os.system("clear")
    else:
        os.system("cls")
    banner()
    num_ports()
    if os.name == "posix":
        os.system("clear")
    else:
        os.system("cls")
    banner()
    # Banner
    scan(target)


def ping(ip_address):
    """
    Pings the given IP address to check if it's active or not.
    """
    response = os.system("ping -n 1 " + ip_address)
    if response == 0:
        alive = True
    else:
        alive = False

    return alive


def funcions(target):
    banner()
    # Añadir funciones preguntando antes de los puertos.
    print(Fore.YELLOW + "Que herramienta quieres utilizar?")
    print(Fore.YELLOW + "-" * 50)
    print(Fore.YELLOW + 'A: --> Port and vuln scan\n \nB: --> Metasploit.\n \nC: --> Subnet Scan')
    fun = None
    while not fun:
        fun = input(Fore.YELLOW + "\n ---> ")
        if 'help' in fun:
            if os.name == "posix":
                os.system("clear")
            else:
                os.system("cls")
            banner()
            print(Fore.GREEN + """---- Usabilidad "PORT SCANNER" v0.3.8 ----
Esta herramienta está pensada para ser muy facil de utilizar.    
Solamente se tiene que escribir el nº máximo de puertos. (500 -- Los primeros 500 Puertos)

1. Se ejecuta un escaneo de puertos para localizar los abiertos

2. Ejecutamos un analisis de servicios de dichos puertos abiertos, identificamos información sobre 
los servicios encontrados 

3. Iniciamos una busqueda de vulnerabilidades públicas en dichos servicios...

4. Tenemos la opcion de buscar en la base de datos de ExploitDb algún exploit público.

5. Podemos abrir metasploit para utilziar la informacion recopilada anteriomente para lo que tengamos que hacer

Para ejecutar este script necesitamos de varios requisitos:
        - NMAP
        - Metasploit (opcional)""")

            print(Fore.YELLOW + "\nQue herramienta quieres utilizar?")
            print("-" * 50)
            print('A: --> Port and vuln scan\n \nB: --> Metasploit.\n \nC: --> Fuzzing')
            fun = None
        elif fun in ['a', 'A']:
            graph(target)
            break

        elif fun in ['b', 'B']:
            input(Fore.YELLOW + "Esta funcion requiere que tengas instalado Metasploit [-ENTER-].")
            try:
                os.system('msfconsole')
                break
            except Exception as error:
                print(Fore.RED + "ERROR: {}\nPrueba a reinstalar o instalar metasploit.".format(error))
        elif fun in ['c', 'C']:
            print('Subetting scan')

        else:
            print(Fore.RED + "Introduce una opción válida, has escogido '{}',"
                             " que no está entre las opciones disponibles".format(fun))
            fun = None


def scan(target):
    # Confirmacion con ping y resultado
    try:
        while True:
            if os.name == "posix":
                os.system("clear")
            else:
                os.system("cls")
            banner()
            # Confirmación con PING?
            p = input(Fore.YELLOW + '¿Quieres hacer una confirmación con PING?\n'
                      'El host puede tener un FireWall bien configurado que bloquee este tipo de paquetes.\n'
                      'Si sabes que esta activo no ejecutes la confirmación. [S/n] -->')

            # En línea o no
            if p in ['S', 's']:
                global alive
                alive = ping(target)
                if alive:
                    if os.name == "posix":
                        os.system("clear")
                    else:
                        os.system("cls")
                    break
                else:
                    print(Fore.YELLOW + "El host no está en línea, saliendo del programa...")
                    exit()
            elif p in ['n', 'N']:
                if os.name == "posix":
                    os.system("clear")
                else:
                    os.system("cls")
                break
            else:
                print(Fore.RED + "Indicación inválida... [S/n]")

        # Inicio del analisis.
        now = datetime.now()
        banner()
        try:
            if alive:
                print(Fore.YELLOW + 'El HOST está en línea.')
        except NameError:
            print(Fore.YELLOW + 'No se ha realizado la confirmación con PING')
        init(now, target)

        for port in range(1, ports + 1):
            try:
                print("\r" + 'Analizando Puerto : %s/%s [%s%s] %.2f%%' % (port, ports, "▓" * int(port * 25 / ports),
                                                                          "▒" * (25 - int(port * 25 / ports)),
                                                                          float(port / ports * 100)), end="")

                # Creamos el Socket para la conexión
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Definimos tiempo máximo de espera a la conexion
                socket.setdefaulttimeout(0.15)
                # creamos la conexion
                result = s.connect_ex((target, port))
                # Si resulta victorioisa la conexion informamos de puerto abierto
                if result == 0:
                    open_ports.append(port)
                    if os.name == "posix":
                        os.system("clear")
                    else:
                        os.system("cls")
                    banner()
                    init(now, target)
                    for open_port in open_ports:
                        print("[♦] - El puerto {} esta abierto.".format(open_port))
                        print("-" * 50)


                s.close()
            # Excepciones del código
            except KeyboardInterrupt:
                end = datetime.now()
                elapsed = end - now
                print(Fore.YELLOW + '\nAnálisis interrumpido en el puerto {}.'.format(port))
                print(Fore.YELLOW + 'Final del análisis --> {}\n'.format(elapsed))
                break
            except Exception as e:
                print("Error inesperado : {}".format(e))

        # Final del analisis
        end = datetime.now()
        if not open_ports:
            elapsed = end - now
            print(Fore.YELLOW + "\nTiempo transcurrido --> {}".format(elapsed))
            print(Fore.YELLOW + "\nNo se han detectado puertos abiertos. :_(")
            exit()
        print(Fore.YELLOW + "\nTiempo transcurrido --> {}".format((end - now)))
        ports_used(open_ports, target)
    # Creamos la salida del programa
    except socket.gaierror:
        print(Fore.RED + "\nNo se ha encontrado el HOST")


def ports_used(open_ports, target):
    # Creamos lista ordenada de puertos para el scaner
    p_str = [str(a) for a in open_ports]
    p_str = (",".join(p_str))
    print(Fore.GREEN + "\n\nLos puertos abiertos son: {}".format(open_ports))
    check_serv(target, p_str, open_ports)


def check_serv(target, p_str, open_ports):
    # Preguntamos si quiere analisis de versiones de servicio
    while True:
        serv = input(Fore.YELLOW + r"[♦] ¿Quieres ejecutar un analisis completo a los puertos abiertos? [S/n] --> ")
        if serv in ["S", 's']:
            break
        elif serv in ['n', 'N']:
            print(Fore.YELLOW + 'Has escojido NO hacer el análisis.\n¿Estas seguro?')
            s = input(Fore.YELLOW + '[S]alir / [E]scanear -->')
            if s in ["S", 's']:
                exit()
            else:
                break
    # Hora del inicio
    init_scan_service = datetime.now()
    # banner del escaneo de servicios
    ascii_part = pyfiglet.figlet_format("Service  SCAN")
    print(ascii_part)
    print("\n" + "-" * 50)

    print("""Escaneando versiones de servicio... 
    ╚══════► Esto puede tardar un poco, vale la pena.\n""")
    print("\nAnálisis iniciado --> {}".format(init_scan_service))
    print("-" * 50 + "\n")



    # Inicio de análisis de nmap
    nm.scan(target, arguments="-p {} --script vuln -sC -sV --version-intensity 5 -A -O".format(p_str))
    end_service_scan = datetime.now()
    dict_serv = {}
    for p in open_ports:
        p = int(p)

        print(Fore.YELLOW + "Analisis puerto nº{} \n".format(p))
        # Recolectamos información del escaneo de servicion anterior y procesamos los datos .
        state = nm[target]['tcp'][int(p)]['state']
        name = nm[target]['tcp'][int(p)]['name']
        product = nm[target]['tcp'][int(p)]['product']
        version = nm[target]['tcp'][int(p)]['version']
        extrainfo = nm[target]['tcp'][int(p)]['extrainfo']
        cpe = nm[target]['tcp'][int(p)]['cpe']
        all_host = None
        try:
            all_host = nm[target]['hostscript']
        except KeyError:
            pass
        # Añadimos al diccionario para la búsqueda de vulners
        if product == "":
            dict_serv[p] = {
                'name': name,
                'version': version,
            }
        else:
            dict_serv[p] = {
                'name': product,
                'version': version,
            }
        # Printeamos los datos

        try:
            script = [nm[target]['tcp'][int(p)]['script'][ind] for ind in nm[target]['tcp'][int(p)]['script']]
            if len(script) <= 1:
                print(
                    Fore.GREEN + "Puerto: {}/{} \n<--> Especificaciones del servicio <--> \n[♦] Nombre: {}  "
                                 "|   Producto: {}  "
                                 "|  Versión: {}  |  {}  |  CPE: {}  \n\nInfo: \n{}  \n"
                    .format(p, state, name, product, version, extrainfo, cpe, script[0]))
                print(Fore.GREEN + "\n" + "-" * 50, "\n")

            else:
                print(Fore.GREEN +
                      "Puerto: {}/{} \n<--> Información del servicio <--> \n[♦] Nombre: {}  |   Producto: {}  "
                      "|  Versión: {}  |  Extra info: {}  |  CPE: {}  \n\nInfo: \n{}\n{}  \n".format(
                          p, state, name, product, version, extrainfo, cpe, script[0], script[1]))
                print(Fore.GREEN + "\n"+"-" * 50, "\n")

        except KeyError:
            print(Fore.GREEN + "Puerto: {}/{} \n<--> Información del servicio <--> \n[♦] Nombre: {}  |   Producto: {}  "
                               "|  Versión: {}  |  Extra info: {}  |  CPE: {}  \n"
                  .format(p, state, name, product, version, extrainfo, cpe))
            print(Fore.GREEN + "\n" + "-" * 50)

    if all_host:
        if len(all_host) > 1:
            print(Fore.YELLOW + "OUTPUTS")
            for information in range(len(all_host)):
                ids = all_host[information]['id']
                if ids == "clock-skew":
                    continue
                else:
                    output = all_host[information]['output']
                    print(Fore.GREEN + f"\n {ids} : {output}")
                    print(Fore.GREEN + "\n" + "═" * 30 + "►", "\n")

    # Tipo de sistema encontrado
    ip = nm[target]['addresses']['ipv4']
    ip_vendor = nm[target]['vendor']
    if not ip_vendor:
        ip_vendor = "N/D"
    name_os = nm[target]['osmatch'][0]['name']
    accuracy = nm[target]['osmatch'][0]['accuracy']
    vendor = nm[target]['osmatch'][0]['osclass'][0]['vendor']
    sys_cpe = nm[target]['osmatch'][0]['osclass'][0]['cpe'][0]

    # Imprimimos la informacion del sistema
    print(Fore.YELLOW + "\nINFORMACIÓN DEL SISTEMA OBJETIVO")
    print(Fore.GREEN + "\n" + "-" * 50, "\n")
    print(Fore.GREEN + "SISTEMA --> {}\n     --\nPrecisión --> {}\n     --\nVendedor --> {}\n     --\n"
                       "CPE: {}\n     --\nIP: {}\n     --\nMAC & Vendor: {}"
          .format(name_os, accuracy, vendor, sys_cpe, ip,[data for data in ip_vendor]))

    elapsed = (end_service_scan - init_scan_service)
    print("\n" + "-" * 50)
    print("Tiempo transcurrido duante el analisis -> {}".format(elapsed))
    # Analisis de vulners?
    while True:
        vuln = input(
            Fore.YELLOW + "\n[♦] ¿Quieres ejecutar un analisis de vulnerabilidades "
                          "a los servicios analizados? [S/n] --> ")
        if vuln in ['S', 's']:
            scan_vuln_services(dict_serv)
            break
        elif vuln in ['N', 'n']:
            exit()
        else:
            print(Fore.RED + 'Introduzca una opción válida... [S/n]')


def scan_vuln_services(dict_serv):
    # Banner vulerns
    ascii_part_2 = pyfiglet.figlet_format("Vulner SCAN")
    vulner = {}
    print(Fore.YELLOW + ascii_part_2)

    print('Abriendo base de datos, espere porfavor')

    vuln = False
    # Busqueda de vulers
    for prt in dict_serv:
        name = dict_serv[prt]['name']
        version = dict_serv[prt]['version']
        service = "{} {}".format(name, version)

        if version == "":
            print(Fore.RED + f'\n[-] No se ha detectado una versión en el serivcio {name}, falta de información para continuar la busqueda. \n')
            continue

        try:
            # Escogemos la mejor opcion o la mas exacta.
            results = nvdlib.searchCVE(keywordSearch=service)[0]
            if name and version not in results:
                results = nvdlib.searchCVE(keywordSearch=service)[1]

            # Procesamos los datos
            cve = results.id
            cpe = results.cpe[0].criteria
            date = results.lastModified
            desc = results.descriptions[0].value
            dificulty = results.metrics.cvssMetricV2[0].cvssData.accessComplexity
            exploit_score = results.v2exploitability
            severity = results.v2severity
            access = results.metrics.cvssMetricV2[0].cvssData.accessVector
            url = results.references[0].url

            print(Fore.GREEN + """\n
[✚] VULNERABILIDAD -> P:{} | SERVICE: {}
═══════════════════════════════════════════════════►
[♦] CVE: {} 
-------------------------------------------------
[♦] CPE: {} 
-------------------------------------------------
[♦] Date: {}              
-------------------------------------------------
[♦] Dificulty: {} 
------------------------------------------------
[♦] Severity: {}
------------------------------------------------
[♦] Risk Score: {}  
-------------------------------------------------
[♦] How to acces: {}     
-------------------------------------------------
[♦] Desciption: {}                        
-------------------------------------------------                                     
[♦]URL: {}                               
═══════════════════════════════════════════════════►""".format(prt, service, cve, cpe, date,
                                                               dificulty, severity,
                                                               exploit_score, access,
                                                               desc, url))
            vulner[cve] = {"name": name,
                           "service": service}
            vuln = True

        # Excepciones para no vulenr
        except IndexError:
            print(Fore.RED + "\n[-] No vulnerabildades detectadas en el servicio {}".format(service))
    if not vuln:
        print(Fore.RED + "\n[-] No se han detectado vulnerabilidades públicas en los sevicios...")
        exit()
    else:
        while True:
            # Buscamos exploits públicos?
            search_exp = input(Fore.YELLOW + '\n¿Deseas buscar exploits en la base de datos de EXPLOITdB? [S/n]')
            if search_exp in ['s', 'S']:
                search_exploit(vulner)
                break
            elif search_exp in ['n', 'N']:
                print("Has escogido NO buscar el exploit.\n")
                if input('¿Seguro?  [C]errar/[B]uscar ->') in ['c', 'C']:
                    print("Cerrando programa")
                    exit()
                else:
                    search_exploit(vulner)
            else:
                print(Fore.RED + "Opción inválida...")


def no_print(pEdb):
    # Creamos un objeto StringIO vacío que descarta los datos
    fake_stdout = io.StringIO()

    # Redirigimos la salida estándar a nuestro objeto StringIO falso
    sys.stdout = fake_stdout

    # Abrimos y actualizamos base de datos
    pEdb.openFile()

    # Restauramos la salida estándar original
    sys.stdout = sys.__stdout__


def search_exploit(vulner):
    # Preparamos la busqueda de exploits
    pEdb = PyExploitDb()
    pEdb.debug = False
    input(Fore.YELLOW + "Esto puede tardar un poco y algunos antivirus lo detectan como virus."
                        " Tendremos a nuestra disposición todos los exploits públicos de ExploitdB."
                        " \n[ENTER] -- [CTRL + C]/Salir \n")

    # Actualizamos abse de datos sin printear en consola
    no_print(pEdb)

    exp = None
    # Buscamos los exploits
    for vlr in vulner:
        results = pEdb.searchCve(vlr)
        try:
            if not results:
                print(Fore.RED + "[-] No se han encontrado exploits públicos para el CVE: {}".format(vlr))
                print("\n", "-" * 50)

            # Procesamos los datos
            else:
                if results['file']:
                    exp = True
                    location = results['file']
                    date = results['date']
                    sistem = results['type']
                    afect = results['platform']
                    desc = results['description']
                    url = results['app_url']
                else:
                    exp = True
                    location = "No found in local."
                    date = results['date']
                    sistem = results['type']
                    afect = results['platform']
                    desc = results['description']
                    url = results['app_url']

                # Printeamos los datos
                print(Fore.YELLOW + '[✚] EXPLOIT ENCONTRADO -> {} '.format(vlr))
                print(Fore.GREEN + """
═══════════════════════════════════════════════════►
[♦] Location: {} 
-------------------------------------------------
[♦] Date: {}              
-------------------------------------------------
[♦] Type: {} 
-------------------------------------------------
[♦] Afected Plataform: {}
-------------------------------------------------
[♦] Desciption: {}                        
-------------------------------------------------                                   
[♦] Exploit URL: {}                              
═══════════════════════════════════════════════════►\n""".format(location, date, sistem, afect, desc, url))
                print("-" * 50, "\n")

        # No exploit encontrado
        except TypeError:
            print(Fore.RED + '[-] No EXPLOIT encontrado en la base de datos.')
            print("-" * 50, "\n")



def main():
    try:
        with open(location + file + extension, "a") as file_log:
            file_log.write("\n SESION DE PORT SCANNER INICIADA --> {}.\n".format(datetime.now()) + "-" * 50)
        # Empezamos código limpiando pantalla
        if os.name == "posix":
            os.system("clear")
        else:
            os.system("cls")

        is_admin()
        check_start()

    # Salida con CTRL + C
    except KeyboardInterrupt:
        print("\n\nSaliendo del programa...")
        exit()


if __name__ == "__main__":
    main()
