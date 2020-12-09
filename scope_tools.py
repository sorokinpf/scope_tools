#!/usr/bin/env python

import ipaddress
import sys
import socket
import os.path
import netaddr
from functools import reduce
import argparse
import pyjq
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.dns import DnsResponse
from nslookup import Nslookup

def gen_network(st):
	st = st.strip()
	if st == '':
		return []
	if '-' in st:
		dash = st.find('-')
		start = st[:dash]
		last_part = st[dash+1:]
		point = len(st) - st[::-1].find('.')
		end = st[:point]+last_part
		return list(netaddr.iter_iprange(start, end))
	return list(ipaddress.ip_network(st))

def dword_from_ip(ip):
	parts = ip.split('.')
	if len(parts)!=4:
		raise Exception('Incorrect ip: %s'%ip)
	res = 0
	for i in range(4):
		res+=int(parts[i])*(256**(3-i))
	return res

def sort_ips(ips):
	ips = sorted(ips,key=dword_from_ip)
	return ips

def read_scope(scope,sort=True):
	scope = scope.split('\n')
	networks = [gen_network(s) for s in scope]
	ips = reduce(lambda x,y: x+y,networks)
	ips = list(set(ips))
	ips = map(str,ips)
	if sort:
		ips = sort_ips(ips)
	return ips

def get_pt_domains_single_ip(ip):
    client = DnsRequest.from_config()
    raw_results = client.get_passive_dns(query=ip)
    domains = pyjq.all('.[].resolve',   raw_results['results'])
    return domains

def get_pt_domains(ip_or_ips_list):
    if isinstance(ip_or_ips_list,list):
        domains = [get_pt_domains_single_ip(ip) for ip in ip_or_ips_list]
        return list(reduce(lambda x,y: x+y,domains))
    else:
        return get_pt_domains_single_ip(ip_or_ips_list)

def resolve_domain(domain, dns_servers = []):
    lookuper = Nslookup(dns_servers=dns_servers)
    return lookuper.dns_lookup(domain).answer

def resolve_domains(domains, dns_servers = [], only_ips=False, only_in_scope=None):
    if only_ips:
        ips = [resolve_domain(domain,dns_servers) for domain in domains]
        ips = list(reduce(lambda x,y: x+y,ips))
        ips = list(set(ips))
        if only_in_scope is not None:
            ips = list(filter(lambda x: x in only_in_scope,ips))
        ips = sort_ips(ips)
        return ips
    pairs = [(domain,resolve_domain(domain,dns_servers)) for domain in domains]
    result = {}
    for pair in pairs:
        for ip in pair[1]:
            if ip in result:
                result[ip].append(pair[0])
            else:
                result[ip] = [pair[0]]
    if only_in_scope is not None:
        filtered_ips = list(filter(lambda x: x in only_in_scope,result))
        result = {k: result[k] for k in filtered_ips}
    result = {k : result[k] for k in sorted(result,key=dword_from_ip)}
    return result
    
def read_scope_file(file_name):
	scope = open(file_name).read()
	parsed = read_scope(scope)
	return parsed
    
def get_scope(args):
	if args.scope is None:
		print ('--scope required for parse_scope')
		exit(1)
	return read_scope_file(args.scope)



def main():
	modes = ['parse_scope','reverse','resolve']
	parser = argparse.ArgumentParser()
	parser.add_argument("mode", help="mode - one of %s"%str(modes), choices= modes)
	parser.add_argument("-s","--scope",	help = "scope file")
	parser.add_argument("-d","--domains", help = "file with domains, one per line")
	parser.add_argument("-r","--resolver", help = "DNS resolver", action='append')
	parser.add_argument("--only-ips", help = "print only ips",default=False, action='store_true')
	parser.add_argument("--only-in-scope", help = 'file with scope ips')
	'''parser.add_argument("-c","--column",
						help="column names. For get mode could by comma separated array of columns")
	parser.add_argument("-w", "--where", 
						help="where clause")
	parser.add_argument('-i','--index',help='index of row')
	parser.add_argument("--threads",help="number of threads",type=int,default=16)
	parser.add_argument('--dbms',help="DBMS",choices= ['mysql','mssql','sqlite','oracle','postgre'])
	parser.add_argument("--order-by",help="order by column name or index")
	parser.add_argument("-s", "--silent",help="not print output during retrieving",default=False, action='store_true')'''

	args = parser.parse_args()
	if args.mode == 'parse_scope':
		parsed = get_scope(args)
		print ('\n'.join(parsed))
		exit(0)
	if args.mode == 'reverse':
		parsed = get_scope(args)
		domains = get_pt_domains(parsed)
		print ('\n'.join(domains))
		exit(0)
	if args.mode == 'resolve':
		if args.domains is None:
			print ('--domains required for parse_scope')
			exit(1)
		print ('resolver: ', args.resolver)
		domains = open(args.domains).read().split('\n')
		only_in_scope = None
		if args.only_in_scope is not None:
			only_in_scope = read_scope_file(args.only_in_scope)
		res = resolve_domains(  domains,
								dns_servers = args.resolver,
								only_ips = args.only_ips,
								only_in_scope = only_in_scope)
		if args.only_ips:
			print ('\n'.join(res))
		else:
			for ip in res:
				print ('\n'.join(['%s\t%s'%(ip,domain) for domain in res[ip]]))




if __name__ == '__main__':
	main()
