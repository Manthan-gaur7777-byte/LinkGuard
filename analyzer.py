from urllib.parse import urlparse, urljoin #join as some sites are lazy and give relative path so we need to join it with base url
import ipaddress
import socket
import ssl
import requests
from ipwhois import IPWhois
import tldextract
import os
from dotenv import load_dotenv
from bs4 import BeautifulSoup
load_dotenv()
#chori ka mal just kidding
def search_threatfox(ioc):
    auth_key = "478e0ca081ef7e1afd324306f63588ce4372861090700cbd"

    if not auth_key:
        return {
            "available": False,
            "found": None,
            "reason": "ThreatFox API key is not configured"
        }

    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={
                "Auth-Key": auth_key
            },
            json={
                "query": "search_ioc",
                "search_term": ioc,
                "exact_match": True
            },
            timeout=10
        )

        response.raise_for_status()
        data = response.json()

        if data.get("query_status") == "no_result":
            return {
                "available": True,
                "found": False,
                "ioc": ioc,
                "source": "ThreatFox"
            }

        if data.get("query_status") == "ok":
            return {
                "available": True,
                "found": True,
                "ioc": ioc,
                "source": "ThreatFox",
                "matches": [
                    {
                        "ioc": item.get("ioc"),
                        "ioc_type": item.get("ioc_type"),
                        "threat_type": item.get("threat_type"),
                        "threat_type_desc": item.get("threat_type_desc"),
                        "malware": item.get("malware"),
                        "confidence_level": item.get("confidence_level"),
                        "first_seen": item.get("first_seen"),
                        "last_seen": item.get("last_seen")
                    }
                    for item in data.get("data", [])
                ]
            }

        return {
            "available": True,
            "found": None,
            "ioc": ioc,
            "source": "ThreatFox",
            "query_status": data.get("query_status")
        }

    except requests.RequestException as e:
        return {
            "available": False,
            "found": None,
            "ioc": ioc,
            "source": "ThreatFox",
            "error": str(e)
        }
def check_urlhaus(url):
    auth_key = "478e0ca081ef7e1afd324306f63588ce4372861090700cbd"

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
def is_public_ip(ip):
    try:
        address = ipaddress.ip_address(ip)

        return (
            address.is_global
            and not address.is_private
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_reserved
        )

    except ValueError:
        return False


def validate_public_host(hostname):
    dns_result = resolve_dns(hostname)

    if not dns_result["success"]:
        return {
            "allowed": False,
            "reason": "DNS resolution failed",
            "addresses": []
        }

    addresses = dns_result["addresses"]

    if not addresses:
        return {
            "allowed": False,
            "reason": "No IP addresses found",
            "addresses": []
        }

    for ip in addresses:
        if not is_public_ip(ip):
            return {
                "allowed": False,
                "reason": f"Host resolves to non-public IP: {ip}",
                "addresses": addresses
            }

    return {
        "allowed": True,
        "reason": None,
        "addresses": addresses
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
            "aliases": aliases,
            "addresses": addresses
        }

    except socket.herror:
        return {
            "success": False,
            "hostname": None,
            "aliases": [],
            "addresses": []
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
    visited = set()
    for hop in range(max_redirects + 1):
        if current_url in visited:
            return {
                "success": False,
                "blocked": True,
                "reason": "Redirect loop detected",
                "hops": hops
            }
        visited.add(current_url) #loop me phasa tha
        parsed_current = urlparse(current_url)
        if not parsed_current.hostname:
            return {
                "success": False,
                "blocked": True,
                "reason": "Invalid hostname",
                "hops": hops
            }
        validation = validate_public_host(parsed_current.hostname)
        #to make me safe if i am hosting
        if not validation["allowed"]:
            return {
                "success": False,
                "blocked": True,
                "reason": validation["reason"],
                "hops": hops
            }
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
def generate_findings(result):
    findings = []
    urlhaus = result.get("urlhaus", {})
    threatfox_url = result.get("threatfox", {}).get("url", {})
    sources = []
    malware = set()
    threat_types = set()
    evidence = []
    if urlhaus.get("found") is True:
        sources.append("URLhaus")
        data = urlhaus.get("data", {})
        if data.get("threat"):
            threat_types.add(data["threat"])
        for tag in data.get("tags", []):
            evidence.append(f"URLhaus tag: {tag}")
        for payload in data.get("payloads", []):
            if payload.get("signature"):
                malware.add(payload["signature"])
    if threatfox_url.get("found") is True:
        sources.append("ThreatFox")
        for match in threatfox_url.get("matches", []):
            if match.get("malware"):
                malware.add(match["malware"])
            if match.get("threat_type"):
                threat_types.add(match["threat_type"])
            if match.get("confidence_level") is not None:
                evidence.append(
                    f"ThreatFox confidence: "
                    f"{match['confidence_level']}%"
                )
    if sources:
        finding = {
            "type": "known_threat_intelligence",
            "title": "Known threat-associated URL",
            "sources": sorted(set(sources)),
            "evidence": evidence
        }
        if malware:
            finding["malware"] = sorted(malware)
        if threat_types:
            finding["threat_types"] = sorted(threat_types)
        findings.append(finding)
    return findings



def build_assessment(findings):
    threat_findings = [
        finding
        for finding in findings
        if finding["type"] == "known_threat_intelligence"
    ]
    if threat_findings:
        return {
            "verdict": "MALICIOUS",
            "confidence": "high",
            "based_on": [
                finding["id"]
                for finding in threat_findings
            ]
        }
    return {
        "verdict": "INSUFFICIENT_EVIDENCE",
        "confidence": "unknown",
        "based_on": []
    }

#mujhe nhi laga thake ham web scraping me aa jae ge per samay ka pahia
def extract_identity(soup, page_url):
    parsed_page = urlparse(page_url)

    page_hostname = parsed_page.hostname
    page_registered_domain = get_registered_domain(
        page_hostname
    ) if page_hostname else None
    title = None
    if soup.title:
        title = soup.title.get_text(strip=True)
    h1 = None
    first_h1 = soup.find("h1")
    if first_h1:
        h1 = first_h1.get_text(strip=True)
    site_name = None
    og_site_name = soup.find(
        "meta",
        attrs={
            "property": "og:site_name"
        }
    )
    if og_site_name:
        site_name = og_site_name.get("content")
    canonical_url = None
    for link in soup.find_all("link"):
        rel = link.get("rel", [])
        if isinstance(rel, str):
            rel = [rel]
        rel = [
            value.lower()
            for value in rel
        ]
        if "canonical" in rel:
            href = link.get("href")
            if href:
                canonical_url = urljoin(
                    page_url,
                    href
                )
            break
    canonical_hostname = None
    canonical_registered_domain = None
    if canonical_url:
        canonical_parsed = urlparse(
            canonical_url
        )
        canonical_hostname = (
            canonical_parsed.hostname
        )
        if canonical_hostname:
            canonical_registered_domain = (
                get_registered_domain(
                    canonical_hostname
                )
            )
    canonical_domain_matches = None
    if (
        page_registered_domain
        and canonical_registered_domain
    ):
        canonical_domain_matches = (
            page_registered_domain
            == canonical_registered_domain
        )

    return {
        "page_hostname": page_hostname,
        "page_registered_domain": page_registered_domain,
        "title": title,
        "h1": h1,
        "site_name": site_name,
        "canonical_url": canonical_url,
        "canonical_hostname": canonical_hostname,
        "canonical_registered_domain": (
            canonical_registered_domain
        ),
        "canonical_domain_matches": (
            canonical_domain_matches
        )
    }
def analyze_html(html, page_url):
    soup = BeautifulSoup(html, "html.parser")
    identity = extract_identity(soup, page_url)
    parsed_page = urlparse(page_url)
    page_host = parsed_page.hostname
    title = None
    if soup.title:
        title = soup.title.get_text(strip=True)
    forms = soup.find_all("form")

    password_fields = soup.find_all(
        "input",
        attrs={"type": "password"}
    )
    form_actions = []
    for form in forms:
        action = form.get("action")
        if not action:
            action = page_url

        absolute_action = urljoin(
            page_url,
            action
        )

        action_host = urlparse(
            absolute_action
        ).hostname

        form_actions.append({
            "action": absolute_action,
            "host": action_host,
            "cross_host": action_host != page_host,
            "contains_password_field": (
                form.find(
                    "input",
                    attrs={"type": "password"}
                ) is not None
            )
        })
    meta_refresh = []       #at first i forgot that meta refresh also redirects (sad)
    for meta in soup.find_all("meta"):
        http_equiv = meta.get("http-equiv")

        if http_equiv and http_equiv.lower() == "refresh":
            meta_refresh.append(
                meta.get("content")
            )
    return {
        "title": title,
        "form_count": len(forms),
        "password_field_count": len(password_fields),
        "form_actions": form_actions,
        "meta_refresh": meta_refresh,
        "identity": identity
    } 


def fetch_html(url, max_bytes=500_000):
    try:
        parsed = urlparse(url)

        if not parsed.hostname:
            return {
                "success": False,
                "reason": "Invalid hostname"
            }

        validation = validate_public_host(
            parsed.hostname
        )

        if not validation["allowed"]:
            return {
                "success": False,
                "reason": validation["reason"]
            }

        response = requests.get(
            url,
            allow_redirects=False,
            timeout=10,
            headers={
                "User-Agent": "LinkGuard/0.1"
            },
            stream=True
        )

        content_type = response.headers.get(
            "Content-Type",
            ""
        ).lower()

        if (
            "text/html" not in content_type
            and "application/xhtml+xml" not in content_type
        ):
            return {
                "success": False,
                "reason": "Response is not HTML",
                "status_code": response.status_code,
                "content_type": content_type
            }

        body = bytearray()

        for chunk in response.iter_content(
            chunk_size=8192
        ):
            if not chunk:
                continue

            remaining = max_bytes - len(body)

            if remaining <= 0:
                break

            body.extend(chunk[:remaining])

            if len(body) >= max_bytes:
                break

        encoding = response.encoding or "utf-8"

        html = body.decode(
            encoding,
            errors="replace"
        )

        return {
            "success": True,
            "status_code": response.status_code,
            "content_type": content_type,
            "html": html,
            "truncated": len(body) >= max_bytes
        }

    except requests.RequestException as e:
        return {
            "success": False,
            "error": str(e)
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

    html_result = None

    if redirect_result.get("success"):
        final_url = redirect_result.get("final_url")

        if final_url:
            fetched = fetch_html(final_url)

            if fetched.get("success"):
                html_result = analyze_html(
                    fetched["html"],
                    final_url
                )
            else:
                html_result = fetched
    registered_domain = get_registered_domain(parsed.hostname)

    threatfox = {
        "url": search_threatfox(url),
        "domain": search_threatfox(registered_domain),
        "ips": []
    }
    if registered_domain:
        threatfox["domain"] = search_threatfox(registered_domain)

    # Search every resolved IP
    for ip in dns_result["addresses"]:
        threatfox["ips"].append({
            "ip": ip,
            "result": search_threatfox(ip)
        })

    result = {
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
        "html_check": html_result,
        "ip_intelligence": ip_intelligence,
        "urlhaus": urlhaus_result,
        "domain_intelligence": domain_intelligence,
        "threatfox": threatfox,
        "signals": signals
    }
    result["findings"] = generate_findings(result)
    if not result["findings"]:
        result["findings"] = [{
            "type": "insufficient_evidence",
            "message": "We are not able to find this url in either ThreatFox or URLhaus."
            " This does not mean that the url is safe, it just means that we don't have any information about it in our threat intelligence sources."
        }]
        
    result["assessment"] = build_assessment(result["findings"])
    return result
