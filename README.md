
## Prepare

Install dependencies

Then add API key for passive total:
```pt-config setup <USERNAME> <API_KEY>```

## Help

```
usage: scope_tools.py [-h] [-s SCOPE] [-d DOMAINS] [-r RESOLVER] [--only-ips]
                      [--only-in-scope ONLY_IN_SCOPE]
                      {parse_scope,reverse,resolve}

positional arguments:
  {parse_scope,reverse,resolve}
                        mode - one of ['parse_scope', 'reverse', 'resolve']

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
```
3. Строим ссылки для брутфорса на основе скана nmap и резолвленных доменов:
```
scope_tools nmap_http --nmap nmap_scan.xml --ips-domains scope_domains.txt --url-format dirsearch - c доменами
scope_tools nmap_http --nmap nmap_scan.xml --ips-domains scope_domains.txt --url-format dirsearch --one-per-port - c доменами, но по 1 штуке на IP, если у нас много IP с большим количеством доменов
scope_tools nmap_http --nmap nmap_scan.xml --url-format dirsearch - только IP
```

результат можно использовать в parallel чтобы все нахрен не сдохло. Так не больше 10 штук одновременно (больше 10 лучше не запускать, при 20 ведет себя неадекватно, например не грузит zsh):
cat dirsearch_task.txt | parallel -j10
