# scanback

Scanback is a daemon that scans you.  You `curl` it with the appropriate HTTP
basic auth credentials and then it runs `nmap -A -Pn` on the IP address you're
scanning from.

If there's a load balancer in the way, it'll scan that instead.  Don't do that.
Scanback should be exposed directly to the internet.

Snake Oil certs were grabbed from [ModSSL](http://www.modssl.org/source/mod_ssl-2.8.30-1.3.39.tar.gz), see LICENSE.snakeoil.

Copy `scanback.conf.sample` to `scanback.conf` and configure it with a username,
password, and paths to your TLS key and certificate.  Then hit it with
```
% curl -u username:password https://localhost:8443
```

You can, of course, specify the bind address, port, etc. through the JSON
config.  You could also use the included snakeoil certs and use `-k` in curl,
but that would be terrible.  Please don't be terrible
