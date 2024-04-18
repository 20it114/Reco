#!/usr/bin/env python3

import os
import sys

R = '\033[31m' #red
G = '\033[32m' #green
C = '\033[36m' #cyan
W = '\033[0m' #white



os.system('tput setaf 6')
print("""

########   ########  ######      #######    
##     ##  ##        ##    ##  ##       ##  
##     ##  ##        ##        ##       ##  
########   ########  ##        ##       ##  
##   ##    ## 	     ##        ##       ##  
##    ##   ##        ##    ##  ##       ##  
##     ##  ########  ########    #######    
      
      
 Author  : Ujjval Patel
 Github  : https://github.com/20it114 
 =========================================
        """)
os.system('tput setaf 3')



import settings as config

home = config.home
usr_data = config.usr_data
conf_path = config.conf_path
path_to_script = config.path_to_script
src_conf_path = config.src_conf_path
meta_file_path = config.meta_file_path

import argparse

version = '1'

parser = argparse.ArgumentParser(description=f'Reco - Reconnaissance Tool  | v{version}')
parser.add_argument('url', help='Target URL')
parser.add_argument('--headers', help='It will get you Header Information', action='store_true')
parser.add_argument('--sslinfo', help='SSL Certificate Information', action='store_true')
parser.add_argument('--whois', help='Whois Lookup', action='store_true')
parser.add_argument('--crawl', help='Crawl Target', action='store_true')
parser.add_argument('--dns', help='DNS Enumeration', action='store_true')
parser.add_argument('--sub', help='Sub-Domain Enumeration', action='store_true')
parser.add_argument('--dir', help='Directory Search', action='store_true')
parser.add_argument('--ps', help='Fast Port Scan', action='store_true')
parser.add_argument('--full', help='Full Recon', action='store_true')

ext_help = parser.add_argument_group('Extra Options')
ext_help.add_argument('-dt', type=int, help='Number of threads for directory enum [ Default : 30 ]')
ext_help.add_argument('-T', type=float, help='Request Timeout [ Default : 30.0 ]')
ext_help.add_argument('-w', help='Path to Wordlist [ Default : wordlists/dirb_common.txt ]')
ext_help.add_argument('-r', action='store_true', help='Allow Redirect [ Default : False ]')
ext_help.add_argument('-s', action='store_false', help='Toggle SSL Verification [ Default : True ]')
ext_help.add_argument('-sp', type=int, help='Specify SSL Port [ Default : 443 ]')
ext_help.add_argument('-d', help='Custom DNS Servers [ Default : 1.1.1.1 ]')
ext_help.add_argument('-e', help='File Extensions [ Example : txt, xml, php ]')
ext_help.add_argument('-o', help='Export Format [ Default : txt ]')
ext_help.set_defaults(
	dt=config.dir_enum_th,
	T=config.timeout,
	w=config.dir_enum_wlist,
	r=config.dir_enum_redirect,
	s=config.dir_enum_sslv,
	sp=config.ssl_port,
	d=config.dir_enum_dns,
	e=config.dir_enum_ext,
	o=config.export_fmt
)

try:
	args = parser.parse_args()
except SystemExit:
	sys.exit()

target = args.url
headinfo = args.headers
sslinfo = args.sslinfo
whois = args.whois
crawl = args.crawl
dns = args.dns
dirrec = args.dir

pscan = args.ps
full = args.full
threads = args.dt
tout = args.T
wdlist = args.w
redir = args.r
sslv = args.s
sslp = args.sp
dserv = args.d
filext = args.e
subd = args.sub
output = args.o

import socket
import subprocess
import datetime
import ipaddress
import tldextract
from json import loads

type_ip = False
data = {}

def full_recon():
	from modules.sslinfo import cert
	from modules.crawler import crawler
	from modules.headers import headers
	from modules.dns import dnsrec
	from modules.whois import whois_lookup
	from modules.dirrec import hammer
	from modules.first import scan_ports
	from modules.subdom import subdomains
	
	headers(target, output, data)
	cert(hostname, sslp, output, data)
	whois_lookup(ip, output, data)
	dnsrec(domain, output, data)
	if type_ip is False:
		subdomains(domain, tout, output, data, conf_path)
	else:
		pass
	scan_ports(ip)
	crawler(target, output, data)
	hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext)
	


try:

	if target.startswith(('http', 'https')) is False:
		print(f'{R}[-] {C}Protocol Missing, Include {W}http:// {C}or{W} https:// \n')
		sys.exit(1)
	else:
		pass

	if target.endswith('/') is True:
		target = target[:-1]
	else:
		pass

	ext = tldextract.extract(target)
	domain = ext.registered_domain
	path_parts = []
	from urllib.parse import urlparse
	url_parts = urlparse(target)
	hostname = url_parts.hostname

	try:
		ipaddress.ip_address(hostname)
		type_ip = True
		ip = hostname
	except Exception:
		try:
			ip = socket.gethostbyname(hostname)
			print(f'\n{G}[+] {C}IP Address : {W}{str(ip)}')
		except Exception as e:
			print(f'\n{R}[-] {C}Unable to Get IP : {W}{str(e)}')
			sys.exit(1)

	start_time = datetime.datetime.now()

	if output != 'None':
		fpath = usr_data
		dt_now = str(datetime.datetime.now().strftime('%d-%m-%Y_%H:%M:%S'))
		fname = f'{fpath}fr_{hostname}_{dt_now}.{output}'
		respath = f'{fpath}fr_{hostname}_{dt_now}'
		if not os.path.exists(respath):
			os.makedirs(respath)
		output = {
			'format': output,
			'directory': respath,
			'file': fname
		}

	if full is True:
		full_recon()

	if headinfo is True:
		from modules.headers import headers
		headers(target, output, data)

	if sslinfo is True:
		from modules.sslinfo import cert
		cert(hostname, sslp, output, data)

	if whois is True:
		from modules.whois import whois_lookup
		whois_lookup(ip, output, data)

	if crawl is True:
		from modules.crawler import crawler
		crawler(target, output, data)

	if dns is True:
		from modules.dns import dnsrec
		dnsrec(domain, output, data)

	if subd is True and type_ip is False:
		from modules.subdom import subdomains
		subdomains(domain, tout, output, data, conf_path)
	elif subd is True and type_ip is True:
		print(f'{R}[-] {C}Sub-Domain Enumeration is Not Supported for IP Addresses{W}\n')
		sys.exit(1)
	else:
		pass

	if pscan is True:
		from modules.first import scan_ports
		scan_ports(ip)

	if dirrec is True:
		from modules.dirrec import hammer
		hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext)

	if any([full, headinfo, sslinfo, whois, crawl, dns, subd, pscan, dirrec]) is not True:
		print(f'\n{R}[-] Error : {C}At least One Argument is Required with URL{W}')
		output = 'None'
		sys.exit(1)

	end_time = datetime.datetime.now() - start_time
	print(f'\n{G}[+] {C}Completed in {W}{str(end_time)}\n')
	print(f'{G}[+] {C}Exported : {W}{respath}')
	sys.exit()
except KeyboardInterrupt:
	print(f'{R}[-] {C}Keyboard Interrupt.{W}\n')
	sys.exit(130)
	
	
