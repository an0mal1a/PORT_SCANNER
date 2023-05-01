try:
    print("\n[♦] Identificando requisitos para la ejecución del programa...\n")
    import concurrent.futures
    import time
    import ctypes
    import string
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
    colorama.init()

    print(Fore.BLUE + "\n[♦]" +
          Fore.YELLOW + " Modulos importados correctamente, procediendo con la ejecución del programa")
    time.sleep(1)
    modules = True
except Exception as e:
    # If there are any errors encountered during the importing of the modules,
    # then we display the error message on the console screen
    print('Existen modulos necesarios que no tiene instalado... \n\n')
    time.sleep(2)
    exit()

if modules:
    nm = nmap.PortScanner()
    open_ports = []


def verifi_tools():

    print(Fore.BLUE + "\n[♦]" +
          Fore.YELLOW + " Verificando herramientas necesarias...")
    time.sleep(1)

    if os.name == "posix":
        if os.system('command -v nmap > /dev/null') != 0:
            print(Fore.RED + "\n[♦] No tienes NMAP instalado...")

        if os.system('command -v msfconsole > /dev/null') != 0:
            print(Fore.RED + "\n[♦] No tienes METASPLOIT instalado...")

    else:
        if os.system("where nmap") != 0:
            print(Fore.RED + "\n[♦] No tienes NMAP instalado...")
            exit()

        if os.system("where nmap") != 0:
            print(Fore.RED + "\n[♦] No tienes METASPLOIT instalado...")



def clean():
    if os.name == "posix":
        os.system("clear")
    else:
        os.system("cls")


def is_admin():
    if os.name == "posix":
        if os.geteuid() != 0:
            print('ESTA HERRAMIENTA NECESITA PERMISOS DE ADMINISTRADOR / ROOT')
            exit()
        
    else:
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            print(Fore.RED + "ESTA HERRAMIENTA NECESITA PERMISOS DE ADMINISTRADOR / ROOT.")
            exit()


def print_help():
    print(Fore.YELLOW + """
        ╔════════════════════════════════════════════════╗
        ║                                                ║
        ║    --  Usabilidad 'PORT SCANNER' v0.4.3  --    ║        
        ║                                                ║
        ╚════════════════════════════════════════════════╝""" +

          Fore.GREEN + "\n\nArgumentos de la herramienta:\n\n" +
          Fore.BLUE + "[♦]" + Fore.YELLOW + " Enter IP --> IP OBETIVO\n" +
    Fore.CYAN + """
            ║       
            ╚═► EJEMPLO --> [♦] ENTER IP -> 127.0.0.1\n""" +

Fore.BLUE + "\n[♦]" + Fore.YELLOW + ' Introduce la cantidad de puertos a escanear - (EJ: 500 - Primeros 500)\n' +

          Fore.CYAN + """ 
            ║       
            ╚═► EJEMPLO --> Introduce cant ports --> 65535 (nº MAX ports)\n""" +


         Fore.YELLOW + "\n\n              -- PROCEDIMIENTO UTILIZADO POR LA HERRAMIENTA --\n\n" +
Fore.CYAN + """1. Se ejecuta un escaneo de puertos para localizar los abiertos

2. Ejecutamos un analisis de servicios de dichos puertos abiertos, identificamos información sobre 
   los servicios encontrados 

3. Iniciamos una busqueda de vulnerabilidades públicas en dichos servicios...

4. Tenemos la opcion de buscar en la base de datos de ExploitDb algún exploit público.

5. Podemos abrir metasploit para utilziar la informacion recopilada
   anteriomente para lo que tengamos que hacer""" +

Fore.GREEN + """\n\nREQUISITOS:\n
            - NMAP
            - Metasploit (opcional)""")


def num_ports():
    global ports
    while True:
        print(Fore.BLUE + "\n[♦]" +
              Fore.YELLOW + ' Introduce la cantidad de puertos a escanear - (EJ: 500 - Primeros 500)')
        ports = input("""
    ╚═► """)
        if 'help' in str(ports):
            clean()
            banner()
            print_help()
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
    
                                                                                © 
 ██▓███   ▒█████   ██▀███  ▄▄▄█████▓     ██████  ▄████▄   ▄▄▄       ███▄    █ 
▓██░  ██▒▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒   ▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ 
▓██░ ██▓▒▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░   ░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
▒██▄█▓▒ ▒▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░      ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
▒██▒ ░  ░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░    ▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░      ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
░▒ ░       ░ ▒ ▒░   ░▒ ░ ▒░    ░       ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
░░       ░ ░ ░ ▒    ░░   ░   ░         ░  ░  ░  ░          ░   ▒      ░   ░ ░ 
             ░ ░     ░                       ░  ░ ░            ░  ░         ░ 
                                                ░                                                                                                 
                                                
       [INFO] Herramienta para analizar puertos de una dirección IP 
             ║                                                 ║                                                                                             
             ║                    v0.4.3                       ║
             ╚══════► Escriba --help para obtener ayuda ◄══════╝
                    \n\n""")


def init(now, target):
    # Inicio del analisis, tiempo y objetivo
    print(Fore.YELLOW + "-" * 55)
    print(Fore.GREEN + "[X] " + Fore.YELLOW + "Objetivo -->" + Fore.RED + f" {target}" +
          Fore.YELLOW + " <--> Nº ports" + Fore.RED + " {}".format(ports))
    print(Fore.GREEN + "[X] " + Fore.YELLOW + "Analisis iniciado --> {}".format(now))
    print("-" * 55)


def graph(target):
    # Escaneo de puertos gráfico
    clean()
    banner()
    num_ports()
    clean()
    banner()
    # Banner
    scan(target)


def funcions(target):
    banner()
    # Añadir funciones preguntando antes de los puertos.
    print(Fore.BLUE + "[♦]" + Fore.YELLOW + " Que herramienta quieres utilizar?")
    print(Fore.YELLOW + "-" * 50)
    print(Fore.BLUE + 'A:' + Fore.YELLOW + ' --> Port and vuln scan' + '\n \n'
          + Fore.BLUE + 'B:' + Fore.YELLOW + ' --> Metasploit.\n')
    fun = None
    while not fun:
        fun = input(Fore.YELLOW + "         ╚═► ")
        if 'help' in fun:
            clean()
            banner()
            print_help()

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
        else:
            print(Fore.RED + "Introduce una opción válida, has escogido '{}',"
                             " que no está entre las opciones disponibles".format(fun))
            fun = None


def ping(ip_address):
    global alive
    while True:
        clean()
        banner()
        # Confirmación con PING?

        p = input(Fore.YELLOW + '¿Quieres hacer una confirmación con PING?\n'
                                'El host puede tener un FireWall bien configurado que bloquee este tipo de paquetes.\n'
                                'Si sabes que esta activo no ejecutes la confirmación. [S/n] -->')

        # En línea o no
        if p in ['S', 's']:

            """
            Pings the given IP address to check if it's active or not.
            """
            response = os.system("ping -n 1 " + ip_address)
            if response == 0:
                alive = True
            else:
                alive = False
            return alive

        elif p in ['n', 'N']:
            alive = None
            break
        else:
            print(Fore.RED + "Indicación inválida... [S/n]")

    return alive


def init_scan(target, now):


    def scaning(port):

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
            clean()
            banner()
            init(now, target)
            for open_port in open_ports:
                print(Fore.BLUE + "[♦]" + Fore.YELLOW + " - El puerto {} esta abierto.".format(open_port), end="")
                print("\n" + "-" * 55 + "\n", end="")
        s.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        futures = []
        for port in range(1, ports + 1):
            try:
                time.sleep(0.08)
                futures.append(executor.submit(scaning, port))
            # Excepciones del código
            except KeyboardInterrupt:
                end = datetime.now()
                elapsed = end - now
                print(Fore.YELLOW + '\n\nAnálisis interrumpido en el puerto {}.'.format(port))
                print(Fore.YELLOW + 'Final del análisis --> {}\n'.format(elapsed))
                break
            except Exception as err:
                print("Error inesperado : {}".format(err))


def scan(target):
    try:
        # Confirmacion con ping y resultado
        ping(target)
        if alive is None:
            pass

        elif not alive:
            a = None
            while not a:
                a = input(Fore.YELLOW + "¿El host no está en línea, quieres salir del programa...? [S/n]\n")
                if a.lower() == "s":
                    exit()
                elif a.lower() == "n":
                    break
                else:
                    print("Introduccion inválida...")

        # Inicio del analisis.
        clean()
        banner()
        if alive:
            print(Fore.YELLOW + 'El HOST está en línea.')
        elif alive is None:
            print(Fore.YELLOW + 'No se ha realizado la confirmación con PING')

    except socket.gaierror:
        print(Fore.RED + "\nNo se ha encontrado el HOST")
    now = datetime.now()
    init(now, target)

    init_scan(target, now)

    # Final del analisis
    end = datetime.now()
    if not open_ports:
        elapsed = end - now
        print(Fore.YELLOW + "\nTiempo transcurrido --> {}".format(elapsed))
        print(Fore.YELLOW + "\nNo se han detectado puertos abiertos. :_(")
        exit()
    print(Fore.YELLOW + "\nTiempo transcurrido --> {}".format((end - now)))
    ports_used(open_ports, target)


def ports_used(open_ports, target):
    # Creamos lista ordenada de puertos para el scaner
    p_str = [str(a) for a in open_ports]
    p_str = (",".join(p_str))
    print(Fore.GREEN + "\n\nLos puertos abiertos son: {}".format(open_ports))
    check_serv(target, p_str, open_ports)


def serv_search():
    while True:
        serv = input(Fore.BLUE + "\n[♦]" + Fore.YELLOW +
                     r" ¿Quieres ejecutar un analisis completo a los puertos abiertos? [S/n] --> ")
        if serv in ["S", 's']:
            break
        elif serv in ['n', 'N']:
            print(Fore.YELLOW + 'Has escojido NO hacer el análisis.' + Fore.RED + '\n¿Estas seguro?')
            s = input(Fore.RED + '[S]' + Fore.GREEN + 'alir / ' +
                      Fore.RED + '[E]' + Fore.GREEN + 'scanear' + Fore.YELLOW + '-->')
            if s in ["S", 's']:
                exit()
            else:
                break


def graph_serv(init_scan_service):
    ascii_part = pyfiglet.figlet_format("Service  SCAN")
    print(ascii_part)
    print("\n" + "-" * 50)

    print(Fore.YELLOW + """Escaneando versiones de servicio... 
        ╚══════► Esto puede tardar un poco, vale la pena.\n""")
    print("\nAnálisis iniciado --> {}".format(init_scan_service))
    print("-" * 50 + "\n")


def check_serv(target, p_str, open_ports):
    # Preguntamos si quiere analisis de versiones de servicio
    serv_search()

    # Hora del inicio
    init_scan_service = datetime.now()

    # banner del escaneo de servicios
    graph_serv(init_scan_service)

    # Inicio de análisis de nmap
    nm.scan(target, arguments="-p {} --script vuln -sS --min-rate 5000 -sC -sV -Pn --version-intensity 3 -n -A -O".format(p_str))
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
                'version': version
            }
        # Printeamos los datos

        try:
            script = [nm[target]['tcp'][int(p)]['script'][ind] for ind in nm[target]['tcp'][int(p)]['script']]
            if len(script) <= 1:
                print(
                    Fore.CYAN + "Puerto: " + Fore.GREEN + f"{p}/{state} \n" + Fore.YELLOW +
                    "<--> Especificaciones del servicio <--> \n" + Fore.BLUE +
                    "[♦]" + Fore.YELLOW + " Nombre:" + Fore.GREEN + f"  {name}  |" +
                    Fore.YELLOW + "  Producto:" + Fore.GREEN + f" {product}   |" +
                    Fore.YELLOW + "  Versión:" + Fore.GREEN + f" {version}  |  {extrainfo}  |  " +
                    Fore.YELLOW + "CPE:" + Fore.GREEN + f" {cpe}  \n\nInfo: \n{script[0]}  \n")

                print(Fore.GREEN + "\n" + "-" * 50, "\n")

            else:
                print(Fore.CYAN +
                      "Puerto: " + Fore.GREEN + f" {p}/{state} \n" + Fore.YELLOW +
                     "<--> Información del servicio <--> \n" + Fore.BLUE + "[♦]" + Fore.YELLOW +
                    " Nombre: " + Fore.GREEN + f"{name}  |   " + Fore.YELLOW + "Producto: " + Fore.GREEN + f"{product}"
                   + Fore.YELLOW + "  |  Versión: " + Fore.GREEN + f"{version}" + Fore.YELLOW + "|  Extra info: " +
                   Fore.GREEN + f"{extrainfo}" + Fore.YELLOW + "|  CPE:" + Fore.GREEN +
                  f"{cpe}  \n\nInfo: \n{script[0]}\n{script[1]}  \n")
                print(Fore.GREEN + "\n"+"-" * 50, "\n")

        except KeyError:
            print(
                Fore.CYAN + "Puerto: " + Fore.GREEN + f"{p}/{state} \n" + Fore.YELLOW +
                "<--> Especificaciones del servicio <--> \n" + Fore.BLUE +
                "[♦]" + Fore.YELLOW + " Nombre:" + Fore.GREEN + f"  {name}"
                                                                "  |  " + Fore.YELLOW + "Producto:" + Fore.GREEN +
                f" {product}    |  " + Fore.YELLOW + "Versión:" + Fore.GREEN + f" {version}  |  {extrainfo}  |  " +
                Fore.YELLOW + "CPE:" + Fore.GREEN + f" {cpe} \n")
            print(Fore.GREEN + "\n" + "-" * 50)


    if all_host is not None:
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

    print_information(target, end_service_scan, init_scan_service, dict_serv)


def print_information(target, end_service_scan, init_scan_service, dict_serv):
    # Tipo de sistema encontrado
    ip = nm[target]['addresses']['ipv4']
    ip_vendor = nm[target]['vendor']
    if not ip_vendor:
        ip_vendor = "N/D"
    name_os = nm[target]['osmatch'][0]['name']
    accuracy = nm[target]['osmatch'][0]['accuracy']
    vendor = nm[target]['osmatch'][0]['osclass'][0]['vendor']
    sys_cpe = nm[target]['osmatch'][0]['osclass'][0]['cpe'][0]

    def how_print():
        if ip_vendor == "N/D":
            return ip_vendor
        else:
            return [data for data in ip_vendor]

    # Imprimimos la informacion del sistema
    print(Fore.YELLOW + "\nINFORMACIÓN DEL SISTEMA OBJETIVO")
    print(Fore.GREEN + "═" * 50 + "►", "\n")
    print(Fore.BLUE + "\nSISTEMA " + Fore.YELLOW + "-->" + Fore.GREEN + f" {name_os}")
    print(Fore.GREEN + "═" * 50 + "►", "\n")
    print(Fore.BLUE +"\nPrecisión " + Fore.YELLOW + "--> " + Fore.GREEN + f"{accuracy}")
    print(Fore.GREEN + "═" * 50 + "►", "\n")
    print(Fore.BLUE + "\nVendedor " + Fore.YELLOW + "--> " + Fore.GREEN + f"{vendor}")
    print(Fore.GREEN + "═" * 50 + "►", "\n")
    print(Fore.BLUE +"\nCPE " + Fore.YELLOW + "--> " + Fore.GREEN + f"{sys_cpe}")
    print(Fore.GREEN + "═" * 50 + "►", "\n")
    print(Fore.BLUE + "\nIP " + Fore.YELLOW + "--> " + Fore.GREEN + f"{ip}")
    print(Fore.GREEN + "═" * 50 + "►", "\n")
    print(Fore.BLUE + "\nMAC & Vendor " + Fore.YELLOW + "--> " + Fore.GREEN + f"{how_print()}")

    elapsed = (end_service_scan - init_scan_service)
    print(Fore.GREEN + "\n" + "-" * 50)
    print(Fore.GREEN + "Tiempo transcurrido duante el analisis -> {}".format(elapsed))

    vlnsrch(dict_serv)


def vlnsrch(dict_serv):
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


def graph_vuln():
    ascii_part_2 = pyfiglet.figlet_format("Vulner SCAN")
    print(Fore.YELLOW + ascii_part_2)
    print('Contactando con la base de datos, espere porfavor')


def scan_vuln_services(dict_serv):
    # Banner vulerns
    graph_vuln()

    count = 0
    vulner = {}

    # Busqueda de vulers
    for prt in dict_serv:
        name = dict_serv[prt]['name']
        version = dict_serv[prt]['version']
        service = "{} {}".format(name, version)

        if version == "":
            print(Fore.RED + f'\n[-] No se ha detectado una versión en el serivcio {name}'
                             f', falta de información para continuar la busqueda.')
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

            print(Fore.GREEN + "\n[+] " + Fore.RED + "VULNERABILIDAD -> P: " + Fore.GREEN + f"{prt}" +
                  Fore.RED + " | SERVICE: " + Fore.GREEN + f"{service}")
            print(Fore.GREEN + "\n═══════════════════════════════════════════════════►")
            print(Fore.BLUE + "\n[♦] " + Fore.RED + "CVE: " + Fore.GREEN + f"{cve}")
            print(Fore.GREEN + "\n-------------------------------------------------")
            print(Fore.BLUE + "\n[♦] " + Fore.RED + "CPE: " + Fore.GREEN + f"{cpe}")
            print(Fore.GREEN + "\n-------------------------------------------------")
            print(Fore.BLUE + "\n[♦] " + Fore.RED + "Date: " + Fore.GREEN + f"{date}")
            print(Fore.GREEN + "\n-------------------------------------------------")
            print(Fore.BLUE + "\n[♦] " + Fore.RED + "Dificulty: " + Fore.GREEN + f"{dificulty}")
            print(Fore.GREEN + "\n------------------------------------------------")
            print(Fore.BLUE + "\n[♦] " + Fore.RED + "Severity: " + Fore.GREEN + f"{severity}")
            print(Fore.GREEN + "\n------------------------------------------------")
            print(Fore.BLUE + "\n[♦] " + Fore.RED + "Risk Score: " + Fore.GREEN + f"{exploit_score}")
            print(Fore.GREEN + "\n-------------------------------------------------")
            print(Fore.BLUE + "\n[♦] " + Fore.RED + "How to acces: " + Fore.GREEN + f"{access}")
            print(Fore.GREEN + "\n-------------------------------------------------")
            print(Fore.BLUE + "\n[♦] " + Fore.RED + "Desciption: " + Fore.GREEN + f"{desc}")
            print(Fore.GREEN + "\n-------------------------------------------------")
            print(Fore.BLUE + "\n[♦] " + Fore.RED + "URL: " + Fore.GREEN + f"{url}")
            print(Fore.GREEN + "\n═══════════════════════════════════════════════════►\n\n")

            vulner[cve] = {"name": name,
                           "service": service}
            count += 1

        # Excepciones para no vulenr
        except IndexError:
            print(Fore.RED + "\n[-] No vulnerabildades detectadas en el servicio {}".format(service))
        except TimeoutError:
            print(Fore.RED + "\n[-] La base de datos no ha respondido a la solicitud...")
            pass

    if count == 0:
        print(Fore.RED + "\n[-] No se han detectado vulnerabilidades públicas en los sevicios...")
        exit()
    else:
        expsrch(vulner)


def expsrch(vulner):
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


def no_print(pedb):
    # Creamos un objeto StringIO vacío que descarta los datos
    fake_stdout = io.StringIO()
    # Redirigimos la salida estándar a nuestro objeto StringIO falso
    sys.stdout = fake_stdout
    # Abrimos y actualizamos base de datos
    pedb.openFile()
    # Restauramos la salida estándar original
    sys.stdout = sys.__stdout__


def search_exploit(vulner):
    # Preparamos la busqueda de exploits
    pedb = PyExploitDb()
    pedb.debug = False
    input(Fore.YELLOW + "Esto puede tardar un poco y algunos antivirus lo detectan como virus."
                        " Tendremos a nuestra disposición todos los exploits públicos de ExploitdB."
                        " \n[ENTER] -- [CTRL + C]/Salir \n")

    # Actualizamos abse de datos sin printear en consola
    no_print(pedb)

    count = 0
    # Buscamos los exploits
    for vlr in vulner:
        results = pedb.searchCve(vlr)
        try:
            if not results:
                print(Fore.RED + "[-] No se han encontrado exploits públicos para el CVE: {}".format(vlr))
                print("\n", "-" * 50)

            # Procesamos los datos
            else:

                count += 1
                location = results['file']
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
    if count == 0:
        print(Fore.RED + '[-] No se han ecnontrado exploits :·( ')


def enter_arguments():
    ip = None
    while not ip:
        try:
            clean()
            banner()
            ip = input(Fore.BLUE + "[♦]" + Fore.YELLOW + " Enter IP --> ")
            # change hostname to IPv4
            if "help" in ip:
                clean()
                banner()
                print_help()
                ip = input(Fore.BLUE + "\n[♦]" + Fore.YELLOW + " Enter IP --> ")
            elif re.findall("[.]", ip) == [".", ".", "."]:
                veryfy = ip.split(".")
                for num in veryfy:
                    if int(num) < 255:
                        continue
                    else:
                        print("\nDirección IPv4 inválida.")
                        time.sleep(2)
                        ip = None
                if ip is not None:
                    try:
                        target = socket.gethostbyname(ip)
                        clean()
                        funcions(target)
                    except socket.gaierror:
                        print('Direccion IPv4 inválida')
                        time.sleep(2)
                        ip = None

            else:
                print(Fore.RED + "Dirección IPv4 inválida")
                time.sleep(2)
                ip = None

        except ValueError:
            print('Debes introducir NUMEROS...')
            print(Fore.RED + """
                ║
                ╠══════► Obligatorio --> Direccion IP / Puertos a analizar.  
                ║
                ╠══════► Tipología   --> <name_script>   
                ║  
                ╚══════► EJEMPLO 	 --> port_scaner """)
            time.sleep(2.5)


def main():
    try:
        # Empezamos código limpiando pantalla
        clean()
        # Miramos si eres admin / root
        is_admin()
        # Verificamos NMAP
        verifi_tools()
        # Iniciamos la herramienta
        enter_arguments()

    # Salida con CTRL + C
    except KeyboardInterrupt:
        print("\n\nSaliendo del programa...")
        exit()


if __name__ == "__main__":
    main()
