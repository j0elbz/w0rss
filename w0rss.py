import os
import subprocess
import re

import nmap
import requests

import sys

from colorama import Fore


clear = lambda:(os.system("clear"))

def ban() -> None:
	print("							  ")
	print("█░░░█ █▀▀█ █▀▀█ █▀▀ █▀▀ ")
	print("█▄█▄█ █▄▀█ █▄▄▀ ▀▀█ ▀▀█ ")
	print("░▀░▀░ █▄▄█ ▀░▀▀ ▀▀▀ ▀▀▀ ")
	print("")
	print("BY   	  JOEL BERMUDEZ4 ")


def get_ttl(host) -> str:
    command = ["ping","-c","1",host]
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    res = p.communicate()[0] 
    res = str(res)  

    res = res.split() 
    ttl = res[11]
    ttl = ttl.split("=") 
    ttl = ttl[-1]

    if int(ttl) >= 64 or int(ttl) <= 64:
        print(f"{Fore.WHITE} TTL approximate to 64 > Device" ,f"{Fore.GREEN} OS ",f" {Fore.WHITE}Linux/Unix")

    elif int(ttl) >= 128 or int(ttl) <= 128:
        print(f"{Fore.WHITE} TTL approximate to 128 >" ,f"{Fore.GREEN} OS ",f" {Fore.WHITE} Windows")
		
    elif int(ttl) >= 254 or int(ttl) <= 254:
        print(f"{Fore.WHITE} TTL approximate to 254 >" ,f"{Fore.GREEN} OS ",f" {Fore.WHITE} Solaris/AIX")
    


def port_scanner(ip) -> None:
	path = ""
	print("Do you want to save port information in a file?")
	decision = input("s/n: ").upper()
	if decision == "S":
		print("Ej: file_name.txt")
		path = input("enter path file > ")
		og = "-oG"
	else:
		og = ""
	
	clear()
	
	ban()

	print("Waiting...","\n")

	nm = nmap.PortScanner()
	
	open_ports="-p "
	results = nm.scan(hosts=ip,arguments=f"-p- -sT -n -Pn {og} {path}")
	count = 0

	for proto in nm[ip].all_protocols():
		print()
		lport = nm[ip][proto].keys()
		sorted(lport)

		for port in lport:
			if nm[ip][proto][port]["state"] == "open":
				state = f"{Fore.GREEN} Open"
				
			else:
				state = f"{Fore.RED} Close"

			print(Fore.WHITE, f"{proto} Port > %s State > %s" % (port,state))
			if count == 0:
				open_ports = open_ports + str(port)
				count = 1
			else:
				open_ports = open_ports + "," + str(port)
	Fore.WHITE
		
def locate_ip(ip) -> str:
    response = requests.post("http://ip-api.com/batch", json=[
    {"query": ip}
    ]).json()

    try:
        for ip_info in response:
            country = ip_info['country']
    except KeyError:
        pass
    try:
        return country
    
    except UnboundLocalError:
        country = f"{Fore.RED} ERROR"




if __name__ == "__main__":
	clear()
	ban()

	try:
		host = sys.argv
		host = str(host[1])
	except IndexError:
		print("You need to enter an ip, example: User > python3 w0rss.py '192.255.255'")
		exit()
	
	port_scanner(host)
	get_ttl(host)
	
	
	country = locate_ip(host)
	if country == None:
		country = f"{Fore.RED} not found".upper() 
	print()
	print(f"Country of the device > {country}")
	
