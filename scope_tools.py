#!/usr/bin/env python

from __future__ import print_function

import ipaddress
import sys
import socket
import os.path
import netaddr
from functools import reduce,partial
import argparse
import pyjq
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.dns import DnsResponse
from nslookup import Nslookup
import xml.etree.ElementTree as ElementTree
from concurrent.futures import ThreadPoolExecutor
import requests
import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

workers = 8

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
    while True:
        try: 
            raw_results = client.get_passive_dns(query=ip)
        except requests.exceptions.RequestException:
            eprint('Request timeout, retrying')
            continue
        break
    domains = pyjq.all('.[].resolve',   raw_results['results'])
    return domains

def get_pt_domains(ip_or_ips_list):
    if isinstance(ip_or_ips_list,list):
        #domains = [get_pt_domains_single_ip(ip) for ip in ip_or_ips_list]
        
        with ThreadPoolExecutor(max_workers=workers) as pool:
            domains = pool.map(get_pt_domains_single_ip,ip_or_ips_list)
            domains = list(domains)
        return list(reduce(lambda x,y: x+y,domains))
    else:
        return get_pt_domains_single_ip(ip_or_ips_list)

def resolve_domain(domain, dns_servers = []):
    lookuper = Nslookup(dns_servers=dns_servers)
    return lookuper.dns_lookup(domain).answer

def resolve_domains(domains, dns_servers = [], 
                    only_ips=False, only_in_scope=None,
                    only_not_in_scope=None):
    if only_ips:
        ips = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            resolve_domain_func = partial(resolve_domain,dns_servers=dns_servers)
            ips = pool.map(resolve_domain_func,domains)
        #ips = [resolve_domain(domain,dns_servers) for domain in domains]
        ips = list(reduce(lambda x,y: x+y,ips))
        ips = list(set(ips))
        if only_in_scope is not None:
            ips = list(filter(lambda x: x in only_in_scope,ips))
        if only_not_in_scope is not None:
            ips = list(filter(lambda x: x not in only_not_in_scope,ips))
        ips = sort_ips(ips)
        return ips
    resolved = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        resolve_domain_func = partial(resolve_domain,dns_servers=dns_servers)
        resolved = pool.map(resolve_domain_func,domains)
    pairs = zip(domains,resolved)
    #pairs = [(domain,resolve_domain(domain,dns_servers)) for domain in domains]
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
    if only_not_in_scope is not None:
        filtered_ips = list(filter(lambda x: x not in only_not_in_scope,result))
        result = {k: result[k] for k in filtered_ips}
    result = {k : result[k] for k in sorted(result,key=dword_from_ip)}
    return result

def get_http_from_nmap(nmap_filename):
    root = ElementTree.parse(nmap_filename).getroot()
    hosts = root.findall('host')

    results = []

    for host in hosts:
        address = host.find('address')
        if address.attrib['addrtype']!='ipv4':
            print ('host %s is not ipv4'%address.attrib['addr'])
            time() #continue
        ip = address.attrib['addr']
        ports = host.findall('ports/port')
        for port in ports:
            if port.attrib['protocol']!='tcp':
                continue
            portnum = port.attrib['portid']
            state = port.find('state')
            if state.attrib['state']!='open':
                continue
            service = port.find('service')
            if 'http' not in service.attrib['name']:
                continue
            ssl=False
            if ('tunnel' in service.attrib):
                if (service.attrib['tunnel']=='ssl'):
                    ssl=True
            else:
                if portnum in ['8443','443']:
                    ssl=True


            results.append((ip,portnum,ssl))
    return results

def get_http_from_cpt(cpt_filename):
    data = open(cpt_filename).read().replace('"','').split('\n')[1:]
    data = map(lambda x: x.split(';'),data)
    data = filter(lambda x: len(x)==6,data)
    data = filter(lambda x: x[4]=='open',data)
    data = filter(lambda x: 'http' in x[2],data)
    data = map(lambda x: (x[0],x[1],'https' in x[2]),data)
    return list(data)

def parse_ip_domain_file(filename):

    data = open(filename).read().split('\n')
    results = {}
    for l in data:
        parts = l.split('\t')
        if len(parts)!=2:
            continue
        if parts[0] in results:
            results[parts[0]].append(parts[1])
        else:
            results[parts[0]] = [parts[1]]
    return results

def build_urls(filename,
                        ip_domains_filename = None,
                        one_per_port = False,
                        input_format='nmap'):
    if input_format=='nmap':
        urls = get_http_from_nmap(filename)
    elif input_format=='cpt':
        urls = get_http_from_cpt(filename)
    else:
        print ('format %s not supported'%input_format)
        exit(1)
    if ip_domains_filename is None:
        return [('https' if url[2] else 'http', url[0], url[1], url[0]) for url in urls]
    ip_domains_table = parse_ip_domain_file(ip_domains_filename)
    results = []

    results_other = []

    for ip,port,ssl in urls:
        if ip not in ip_domains_table:
            #u = '%s://%s:%s'%('https' if ssl else 'http', ip, port)
            results.append(('https' if ssl else 'http', ip, port,ip))
            continue
        
        #u = '%s://%s:%s'%('https' if ssl else 'http', ip_domains_table[ip][0], port)
        results.append(('https' if ssl else 'http', ip, port,ip_domains_table[ip][0]))
        #results.append((u,ip))
        if one_per_port:
            continue
        for domain in ip_domains_table[ip][1:]:
            #u = '%s://%s:%s'%('https' if ssl else 'http', domain, port)
            results_other.append(('https' if ssl else 'http', ip, port,domain))
            #results.append((u,ip))
    return results+results_other

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
    modes = ['parse_scope','reverse','resolve','build_http']
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", help="mode - one of %s"%str(modes), choices= modes)
    parser.add_argument("-s","--scope",    help = "scope file")
    parser.add_argument("-d","--domains", help = "file with domains, one per line")
    parser.add_argument("-r","--resolver", help = "DNS resolver", action='append')
    parser.add_argument("--only-ips", help = "print only ips",default=False, action='store_true')
    parser.add_argument("--only-in-scope", help = 'file with scope ips')
    parser.add_argument("--only-not-in-scope", help = 'file with scope ips for exclude')
    parser.add_argument('--input', help='input file for building http')
    parser.add_argument('--input-format',choices= ['nmap','cpt'],default='nmap')
    parser.add_argument('--ips-domains', 
                    help = 'file with \'IP\tdomain\' per line, result of \'resolve\' mode')
    parser.add_argument('--one-per-port', 
                    help = 'return only one line for every nmap port even if more than 1 domain resolve to this IP',
                    default=False, 
                    action='store_true')
    url_formats = ['dirsearch','ffuf','url','dirsearch_new']
    parser.add_argument('--url-format',
                    help ='one of %s'%str(url_formats),
                    choices=url_formats,
                    default='url')
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
        domains = list(set(domains))
        print ('\n'.join(domains))
        exit(0)
    if args.mode == 'resolve':
        if args.domains is None:
            print ('--domains required for parse_scope')
            exit(1)
        domains = open(args.domains).read().lower().split('\n')
        domains = list(set(domains))
        only_in_scope = None
        only_not_in_scope = None
        if args.only_in_scope is not None:
            only_in_scope = read_scope_file(args.only_in_scope)
        if args.only_not_in_scope is not None:
            only_not_in_scope = read_scope_file(args.only_not_in_scope)
        

        res = resolve_domains(  domains,
                                dns_servers = args.resolver,
                                only_ips = args.only_ips,
                                only_in_scope = only_in_scope,
                                only_not_in_scope = only_not_in_scope)
        if args.only_ips:
            print ('\n'.join(res))
        else:
            for ip in res:
                print ('\n'.join(['%s\t%s'%(ip,domain) for domain in res[ip]]))
    if args.mode == 'build_http':
        if args.input is None:
            print ('--input required for this mode')
            exit(1)
        urls = build_urls(args.input,
                                input_format = args.input_format,
                                ip_domains_filename = args.ips_domains,
                                one_per_port=args.one_per_port)
        if args.url_format == 'dirsearch':
            print ('\n'.join(['dirsearch -u %s://%s:%s --ip %s -e js,jsp,json,php,asp,aspx -w ~/dicts/medium_wordlist.txt --csv-report=%s-%s-%s-%s.csv' % (schema,domain,port,ip,ip,port,schema,domain) for schema,ip,port,domain in urls]))
        if args.url_format == 'dirsearch_new':
            print ('\n'.join(['dirsearch -u %s://%s:%s --ip %s -e js,jsp,json,php,asp,aspx -w ~/dicts/medium_wordlist.txt -o %s-%s-%s-%s.csv --format=csv' % (schema,domain,port,ip,ip,port,schema,domain) for schema,ip,port,domain in urls]))
        if args.url_format == 'ffuf':
            print ('\n'.join(['ffuf -u %s://%s:%s -H "Host: %s:%s"' % (schema,ip,port,domain,port) for schema,ip,port,domain in urls]))
        if args.url_format == 'url':
            print ('\n'.join(['%s://%s:%s' % (schema,ip,port) for schema,ip,port,domain in urls]))


if __name__ == '__main__':
    main()
