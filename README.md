# PORT_SCANNER

# Autor: __TownPablo__


print(Fore.YELLOW + """
        ╔════════════════════════════════════════════════╗
        ║                                                ║
        ║    --  Usabilidad 'PORT SCANNER' v0.4.0  --    ║        
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
            
            
