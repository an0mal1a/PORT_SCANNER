import re, sys, subprocess

# python wichSystem.py 127.0.0.1

"""if len(sys.argv) != 2:
    print("\n[!] USO: python " + sys.argv[0] + " <ip_address>\n")
    sys.exit(1)
"""

def get_ttl(ip_address):
    try:
        proc = subprocess.Popen(["ping", "-n", "1", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()

        out = out.split()
        out = out[14].decode()

        ttl = re.findall(r"\d{1,3}", out)[0]

        return ttl
    except IndexError:
        return 1000


def get_os(ttl):

    ttl = int(ttl)

    if ttl >= 0 and ttl <= 64:
        return "Linux"
    elif ttl >= 65 and ttl <= 128:
        return "Windows"
    else:
        return "Not Found"


def init_guess(ip):
    try:
        ttl = get_ttl(ip)

        os_name = get_os(ttl)

        if ttl == 1000:
            ttl = "N/A"
        return ("(ttl --> {}): {}".format(ttl, os_name))

    except TypeError:
        print("\n[!] USO: python " + sys.argv[0] + " <ip_address>\n")
        sys.exit(1)


if __name__ == "__main__":
    try:
        ip_address = sys.argv[1]

        ttl = get_ttl(ip_address)

        os_name = get_os(ttl)

        print("{} (ttl --> {}): {}".format(ip_address, ttl, os_name))

    except TypeError:
        print("\n[!] USO: python " + sys.argv[0] + " <ip_address>\n")
        sys.exit(1)

"""import re
import sys
import subprocess

if len(sys.argv) != 2:
    print("\n[!] USO: python " + sys.argv[0] + " <ip_address>\n")
    sys.exit(1)

def get_ttl(ip_address):
    proc = subprocess.Popen(["ping", "-n", "1", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()

    out = out.decode()
    ttl = re.findall(r"TTL=\d+", out)
    if ttl:
        return int(ttl[0].split('=')[1])
    else:
        return None

def get_os(ttl):
    if ttl is None:
        return "Not Found"
    elif ttl >= 0 and ttl <= 64:
        return "Linux/Unix"
    elif ttl >= 65 and ttl <= 128:
        return "Windows"
    else:
        return "Not Found"

if __name__ == "__main__":
    try:
        ip_address = sys.argv[1]

        ttl = get_ttl(ip_address)

        os_name = get_os(ttl)

        print("{} (ttl --> {}): {}".format(ip_address, ttl, os_name))

    except TypeError:
        print("\n[!] USO: python " + sys.argv[0] + " <ip_address>\n")
        sys.exit(1)"""