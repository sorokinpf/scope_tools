
## Prepare

Install dependencies

Then add API key for passive total:
```pt-config setup <USERNAME> <API_KEY>```

## Help

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
