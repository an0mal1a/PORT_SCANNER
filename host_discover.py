import time
from pathlib import Path
import scapy.all as scapy
import colorama
from colorama import Fore
from os_guess import init_guess
colorama.init()


def get_user_path():
    return "{}/".format(Path.home())


def write_file(text):
    userpath = get_user_path()
    location = userpath + "/Desktop/"
    filename = "scan.log"

    with open(location + filename, "a", encoding="utf-8") as log:
        now = str(time.ctime())
        log.write("\n<<< " + now + " >>> " + text)


def scan_network(ip):
    # Crear un objeto ARP request para obtener la dirección MAC de los dispositivos en la red
    arp_request = scapy.ARP(pdst=ip)

    # Crear un objeto Ethernet frame para enviar el paquete ARP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combinar el paquete ARP con el frame Ethernet
    arp_request_broadcast = broadcast / arp_request

    # Enviar y recibir paquetes
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Crear una lista vacía para almacenar los dispositivos descubiertos
    clients_list = []

    # Recorrer la lista de dispositivos descubiertos y obtener sus direcciones IP y MAC
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    # Retornar la lista de dispositivos
    return clients_list


def discove(target):
    # Ejemplo de uso
    try:
        scan_result = scan_network(target)
        scaned = 0
        for device in scan_result:
            scaned += 1
            ip = device['ip']
            mac = device["mac"]
            os = init_guess(ip)

            # Print en el archivo
            write_file('[!] Detected Device:\n')

            # Print Consola
            print(Fore.RED + "\t[♦] " + Fore.GREEN + f"Device --> {scaned}\n")
            print(Fore.CYAN + "\t\tIP: " + Fore.WHITE + f'{ip}')
            print(Fore.CYAN + "\t\tMAC: " + Fore.WHITE + f"{mac}")
            print(Fore.CYAN + "\t\tOS GUEST: " + Fore.WHITE + f"{os}\n")

            # Print en el archivo
            write_file(f" Device --> {scaned}")
            write_file(f"\t\t IP ADDRESS: {ip}")
            write_file(f"\t\t MAC ADDRESS: {mac}")
            write_file(f"\t\t OS GUEST: {os}\n")
            write_file("\n" + "═" * 80 + "\n")

        input("\nScan Results saved in file 'scan.log'\n[ENTER] --> To Continue...")
    except Exception as e:
        print("Ha surgido un error... \n", e)


if __name__ == "__main__":
    ip = "192.168.131.4/24"
    discove(ip)
