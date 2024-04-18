#!/usr/bin/env python3

import aiohttp
import asyncio
from modules.export import export


from modules.subdomain_modules.anubis_subs import anubisdb
from modules.subdomain_modules.thminer_subs import thminer
from modules.subdomain_modules.certspot_subs import certspot
from modules.subdomain_modules.crtsh_subs import crtsh
from modules.subdomain_modules.htarget_subs import hackertgt

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

found = []


async def query(hostname, tout, conf_path):
	timeout = aiohttp.ClientTimeout(total=tout)
	async with aiohttp.ClientSession(timeout=timeout) as session:
		await asyncio.gather(
			anubisdb(hostname, session),
			thminer(hostname, session),
			certspot(hostname, session),
			hackertgt(hostname, session),
			crtsh(hostname)
		)
	await session.close()


def subdomains(hostname, tout, output, data, conf_path):
	global found
	result = {}

	print(f'\n{Y}[!] Starting Sub-Domain Enumeration...{W}\n')

	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	loop.run_until_complete(query(hostname, tout, conf_path))
	loop.close()

	found = [item for item in found if item.endswith(hostname)]
	valid = r"^[A-Za-z0-9._~()'!*:@,;+?-]*$"
	from re import match
	found = [item for item in found if match(valid, item)]
	found = set(found)
	total = len(found)

	if len(found) != 0:
		print(f'\n{G}[+] {C}Results : {W}\n')
		for url in found:
			print(url)

	print(f'\n{G}[+] {C}Total Unique Sub Domains Found : {W}{total}')

	if output != 'None':
		result['Links'] = list(found)
		result.update({'exported': False})
		data['module-Subdomain Enumeration'] = result
		fname = f'{output["directory"]}/subdomains.{output["format"]}'
		output['file'] = fname
		export(output, data)
