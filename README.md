# scanback

Scanback is a daemon that scans you.  You `curl` it with the appropriate HTTP
basic auth credentials and then it runs `nmap -A -Pn` on the IP address you're
scanning from.

If there's a load balancer in the way, it'll scan that instead.  Don't do that.
Scanback should be exposed directly to the internet.

Snake Oil certs were grabbed from [ModSSL](http://www.modssl.org/source/mod_ssl-2.8.30-1.3.39.tar.gz), see LICENSE.snakeoil.

