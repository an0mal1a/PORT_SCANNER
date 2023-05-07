#                   PORT_SCANNER

Autor: _An0mal1a_



#  --  Usabilidad 'PORT SCANNER' v0.4.4.a  --       

Argumentos de la herramienta:

    [♦] Enter IP --> IP OBETIVO    

    ║       
    ╚═► EJEMPLO --> [♦] ENTER IP -> 127.0.0.1

    [♦] Introduce la cantidad de puertos a escanear - (EJ: 500 - Primeros 500)

    ║               
    ╚═► EJEMPLO --> Introduce cant ports --> 65535 (nº MAX ports)
    
    [♦] Si posee conocimientos de nmap, opcion de añadir argumentos

   -- PROCEDIMIENTO UTILIZADO POR LA HERRAMIENTA --
          
    1. Se ejecuta un escaneo de puertos para localizar los abiertos

    2. Ejecutamos un analisis de servicios de dichos puertos abiertos,
       identificamos información sobre los servicios encontrados 

    3. Iniciamos una busqueda de vulnerabilidades públicas en dichos servicios...

    4. Tenemos la opcion de buscar en la base de datos de ExploitDb algún exploit público.

    5. Podemos abrir metasploit para utilziar la informacion recopilada
       anteriomente para lo que tengamos que hacer
    
    REQUISITOS:
            - NMAP
            - Metasploit (opcional)
            
Se han añadido funciones para crear un archivo 'scan.log' en el escritorio.
Se han añadido Host Discovery y Os_guess que en base el ttl no dice de forma simple el OS que corre 
Se han corregido errores
En mejora argumentos personalizados de "NMAP"


# Pip:

    command_line = pip install python-scan

# Git:
    command_line = git clone https://github.com/TownPablo/PORT_SCANNER
    cd PORT_SCANNER
    sudo python setup.py install

# Linux 
    Una vez instalado (pip)
        ║               
        ╚═► 1. ┌[parrot]─[20:12-03/05]─[/home/supervisor]
               └╼supervisor$whereis PORT_SCAN   
                PORT_SCAN: /usr/local/bin/PORT_SCAN.py
            
            2. sudo chmod +x /usr/local/bin/PORT_SCAN.py
            3. python3 /usr/local/bin/PORT_SCAN.py
    
    Opcion Recomendada (Ejecución de cualquier ruta):
       Una vez instalado (git)
           ║               
           ╚═► 1. PORT_SCAN.py

             ┌─[supervisor@parrot]─[/]
             └──╼ $ PORT_SCAN.py


# Windows
        Ejecución desde cualquier ruta

            1. pip install python-scan
            2. port_scan / port_scan.py
