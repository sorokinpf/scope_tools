#!/usr/bin/env python

import ipaddress
import sys
import socket
import os.path
import netaddr

def gen_network(st):
	if '-' in st:
		dash = st.find('-')
		start = st[:dash]
		last_part = st[dash+1:]
		point = len(st) - st[::-1].find('.')
		end = st[:point]+last_part
		return list(netaddr.iter_iprange(start, end))
	return list(ipaddress.ip_network(st))

def main():

	if len(sys.argv) !=2:
		print ('usage: is_in_scope <address>')
		sys.exit(1)

	scope_file = '/curr_proj/scope.txt'
	if not os.path.exists(scope_file):
		print ('scope.txt not defined in ~/curr_proj')
		sys.exit(1)
	scope = open(scope_file).read()
	scope = scope.split('\n')
	networks = [gen_network(s) for s in scope]
	arg = sys.argv[1]
	arg = arg.replace('http://','').replace('https://','').replace('/','')
	if ':' in arg:
		arg = arg[:arg.find(':')]

	try:
		ip_arg = ipaddress.ip_address(arg)
	except ValueError as e:
		try:
			ip = socket.gethostbyname_ex(arg)[2][0]
		except socket.gaierror as e:
			print ('coudn\'t resolve %s'%arg)
			sys.exit(1)
		print ('Resolved %s to %s'%(arg,ip))
		ip_arg = ipaddress.ip_address(ip)

	if(sum([ip_arg in net for net in networks]))>0:
		print ('Host %s is in scope' % arg)
	else:
		print ('Host %s is not in scope' % arg)

if __name__=='__main__':
	main()
