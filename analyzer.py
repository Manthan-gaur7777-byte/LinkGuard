from urllib.parse import urlparse, urljoin #join as some sites are lazy and give relative path so we need to join it with base url
import ipaddress
import socket
import ssl
import requests
from ipwhois import IPWhois
import tldextract
import os
from dotenv import load_dotenv

load_dotenv()
#chori ka mal just kidding

def check_urlhaus(url):
    auth_key = "your auth key"

    if not auth_key:
        return {
            "available": False,
            "found": None,
            "reason": "URLhaus API key is not configured"
        }

    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": auth_key},
            timeout=10
        )

        response.raise_for_status()
        data = response.json()

        query_status = data.get("query_status")

        if query_status == "ok":
            return {
                "available": True,
                "found": True,
                "source": "URLhaus",
                "data": data
            }

        if query_status == "no_results":
            return {
                "available": True,
                "found": False,
                "source": "URLhaus"
            }

        return {
            "available": True,
            "found": None,
            "source": "URLhaus",
            "query_status": query_status
        }

    except requests.RequestException as e:
        return {
            "available": False,
            "found": None,
            "source": "URLhaus",
            "error": str(e)
        }
def get_registered_domain(hostname):#www.falana.com->falana.com
    extracted = tldextract.extract(hostname)

    return extracted.top_domain_under_public_suffix
def is_ip_address(hostname):#isi leye toda tha
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False
def has_userinfo(url):
    
    parsed = urlparse(url)
    return parsed.username is not None
#yana ake laga kya kar rahe ru me ye ya kun
def is_long_url(url):
    return len(url) > 100
def check_ip_hostname(hostname):
    detected = is_ip_address(hostname)

    return {
        "name": "IP hostname",
        "detected": detected,
        "severity": "medium" if detected else "none",
        "explanation": (
            "The URL uses an IP address instead of a domain name."
            if detected
            else "The URL uses a domain name."
        )
    }
def check_https(scheme):
    detected = scheme != "https"

    return {
        "name": "No HTTPS",
        "detected": detected,
        "severity": "medium" if detected else "none",
        "explanation": (
            "The URL does not use HTTPS."
            if detected
            else "The URL uses HTTPS."
        )
    }
def check_userinfo(url):
    detected = has_userinfo(url)

    return {
        "name": "URL contains userinfo",
        "detected": detected,
        "severity": "high" if detected else "none",
        "explanation": (
            "The URL contains userinfo before the hostname, which can be used to disguise the true destination."
            if detected
            else "The URL does not contain userinfo."
        )
    }
def check_long_url(url):
    detected = is_long_url(url)

    return {
        "name": "Unusually long URL",
        "detected": detected,
        "severity": "low" if detected else "none",
        "explanation": (
            "The URL is unusually long and should be examined further."
            if detected
            else "The URL length is within the current threshold."
        )
    }
def resolve_dns(hostname):
    try:
        results = socket.getaddrinfo(#ese pahle bas ek ip de raha tha 
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        addresses = sorted({
            result[4][0]    #log bol rahe ki remove duplicates
            for result in results
        })

        return {
            "success": True,
            "addresses": addresses
        }

    except socket.gaierror as e:
        return {
            "success": False,
            "addresses": [],
            "error": str(e)
        }
def reverse_dns(ip):
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        return {
            "success": True,
            "hostname": hostname,
            "aliases": aliases
        }

    except socket.herror:
        return {
            "success": False,
            "hostname": None,
            "aliases": []
        }
#looking for ASN using RDAP 
def get_ip_intel(ip):
    try:
        result = IPWhois(ip).lookup_rdap()

        network = result.get("network") or {}

        return {
            "success": True,
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description"),
            "network_name": network.get("name"),
            "network_cidr": network.get("cidr"),
            "country": network.get("country")
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
def get_domain_intelligence(hostname):
    registered_domain = get_registered_domain(hostname)

    if not registered_domain:
        return {
            "success": False,
            "error": "Could not determine registered domain"
        }

    try:
        response = requests.get(
            f"https://rdap.org/domain/{registered_domain}",
            timeout=10,
            headers={
                "User-Agent": "LinkGuard/0.1"
            }
        )

        if response.status_code != 200:
            return {
                "success": False,
                "registered_domain": registered_domain,
                "status_code": response.status_code
            }

        data = response.json()

        events = {}

        for event in data.get("events", []):
            action = event.get("eventAction")
            date = event.get("eventDate")

            if action and date:
                events[action] = date

        nameservers = []

        for nameserver in data.get("nameservers", []):
            name = nameserver.get("ldhName")

            if name:
                nameservers.append(name)

        return {
            "success": True,
            "registered_domain": registered_domain,
            "handle": data.get("handle"),
            "status": data.get("status", []),
            "registration": events.get("registration"),
            "last_changed": events.get("last changed"),
            "expiration": events.get("expiration"),
            "nameservers": nameservers
        }

    except (requests.RequestException, ValueError) as e:
        return {
            "success": False,
            "registered_domain": registered_domain,
            "error": str(e)
        }
#damn ye sab to me bhi pheli bar dekha
def get_tls_info(hostname, port=443):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=5) as sock:#to get address and socket
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:#for hand shake and get the certificate
                certificate = tls_sock.getpeercert()

        return {
            "success": True,
            "subject": certificate.get("subject"),
            "issuer": certificate.get("issuer"),
            "valid_from": certificate.get("notBefore"),
            "valid_until": certificate.get("notAfter")
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
def inspect_redirects(url, max_redirects=10):
    current_url = url
    hops = []

    for hop in range(max_redirects + 1):

        try:
            response = requests.get(
                current_url,
                allow_redirects=False,
                timeout=10,
                headers={
                    "User-Agent": "LinkGuard/0.1"
                },
                stream=True
            )

        except requests.RequestException as e:
            return {
                "success": False,
                "hops": hops,
                "error": str(e)
            }

        next_url = response.headers.get("Location")

        parsed_current = urlparse(current_url)

        hop_data = {
            "hop": hop,
            "url": current_url,
            "host": parsed_current.hostname,
            "status_code": response.status_code,
            "server": response.headers.get("Server"),
            "location": next_url
        }

        if next_url:
            next_url = urljoin(current_url, next_url)

            parsed_next = urlparse(next_url)

            hop_data["next_url"] = next_url
            hop_data["scheme_changed"] = (
                parsed_current.scheme != parsed_next.scheme
            )
            hop_data["host_changed"] = (
                parsed_current.hostname != parsed_next.hostname
            )

        hops.append(hop_data)

        if not next_url:
            return {
                "success": True,
                "redirect_count": len(hops) - 1,
                "final_url": current_url,
                "hops": hops
            }

        current_url = next_url

    return {
        "success": False,
        "redirect_count": len(hops) - 1,
        "final_url": current_url,
        "hops": hops,
        "error": "Maximum redirect limit reached"
    }
def analyze_url(url):
    
    parsed = urlparse(url)
    if not parsed.hostname:
        return {
                "original_url": url,
                "valid": False,
                "error": "Could not determine a hostname"
            }
    signals = [
        check_https(parsed.scheme),
        check_ip_hostname(parsed.hostname),
        check_userinfo(url),
        check_long_url(url)
    ]

    dns_result = resolve_dns(parsed.hostname)
    tls_result = None
    dns_result = resolve_dns(parsed.hostname)
    ip_intelligence = []
    urlhaus_result = check_urlhaus(url)
    for ip in dns_result["addresses"]:
        ip_intelligence.append({
            "ip": ip,
            "intelligence": get_ip_intel(ip)
        })
    reverse_dns_result = []
    domain_intelligence = get_domain_intelligence(parsed.hostname)
    for ip in dns_result["addresses"]:
        reverse_dns_result.append({
            "ip": ip,
            "reverse_dns": reverse_dns(ip)
        })
    if parsed.scheme == "https":
        tls_result = get_tls_info(parsed.hostname, parsed.port or 443)
    redirect_result = inspect_redirects(url)
    return {
        "original_url": url,
        "scheme": parsed.scheme,#like http or https
        "domain": parsed.netloc,# like example.com and port both so
        "HostName": parsed.hostname,
        "port":parsed.port,
        "path": parsed.path,#/ke aage ka
        "query": parsed.query,# go hum get me bhej te he
        "dns": dns_result,
        "reverse_dns": reverse_dns_result,
        "tls": tls_result,
        "redirects": redirect_result,
        "ip_intelligence": ip_intelligence,
        "urlhaus": urlhaus_result,
        "domain_intelligence": domain_intelligence,
        "signals": signals
    }
