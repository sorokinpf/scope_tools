
## Install

```pip install -r requirements.txt```

Then add API key for passive total:
```pt-config setup <USERNAME> <API_KEY>```

## Help

```
usage: scope_tools.py [-h] [-s SCOPE] [-d DOMAINS] [-r RESOLVER] [--only-ips]
                      [--only-in-scope ONLY_IN_SCOPE] [--input INPUT]
                      [--input-format {nmap,cpt}] [--ips-domains IPS_DOMAINS]
                      [--one-per-port] [--url-format {dirsearch,ffuf}]
                      {parse_scope,reverse,resolve,build_http}

positional arguments:
  {parse_scope,reverse,resolve,build_http}
                        mode - one of ['parse_scope', 'reverse', 'resolve',
                        'build_http']

optional arguments:
  -h, --help            show this help message and exit
  -s SCOPE, --scope SCOPE
                        scope file
  -d DOMAINS, --domains DOMAINS
                        file with domains, one per line
  -r RESOLVER, --resolver RESOLVER
                        DNS resolver
  --only-ips            print only ips
  --only-in-scope ONLY_IN_SCOPE
                        file with scope ips
  --only-not-in-scope ONLY_NOT_IN_SCOPE
                        file with scope ips for exclude
  --input INPUT         input file for building http
  --input-format {nmap,cpt}
  --ips-domains IPS_DOMAINS
                        file with 'IP domain' per line, result of 'resolve'
                        mode
  --one-per-port        return only one line for every nmap port even if more
                        than 1 domain resolve to this IP
  --url-format {dirsearch,ffuf}
                        one of ['dirsearch', 'ffuf']
```

## Заметка

Моя подделка для анализа скоупа.

Типовые решаемые задачи:
1. реверс IP адресов с помощью passive total:
```
scope_tools reverse -s scope > reversed_domains.txt
```

2. резолв полученных доменов с отсеиванием тех что не в скоупе:
```
scope_tools resolve -d reversed_domains.txt --only-in-scope scope > scope_domains.txt - так получаем связки IP:domain
scope_tools resolve -d reversed_domains.txt --only-ips --only-in-scope scope > scope_ips.txt - так только IP
scope_tools resolve -d reversed_domains.txt --only-not-in-scope scope > scope_ips.txt - так только те что вне скоупа, так сказать на согласование
```

3. Строим ссылки для брутфорса на основе скана nmap и резолвленных доменов:
```
scope_tools build_http --input-format nmap --input nmap_scan.xml --ips-domains scope_domains.txt --url-format dirsearch - c доменами
scope_tools build_http --input-format nmap --input nmap_scan.xml --ips-domains scope_domains.txt --url-format dirsearch --one-per-port - c доменами, но по 1 штуке на IP, если у нас много IP с большим количеством доменов
scope_tools build_http --input-format nmap --input nmap_scan.xml - только IP
```

результат можно использовать в parallel чтобы все нахрен не сдохло. Так не больше 10 штук одновременно (больше 10 лучше не запускать, при 20 ведет себя неадекватно, например не грузит zsh):
cat dirsearch_task.txt | parallel -j10
