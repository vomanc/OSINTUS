''' These are scripts that check by ip, mac, domain'''
import urllib.request
import json
import time
from extension import IPINFO_TOKEN, VIRUSTOTAL_TOKEN, UESR_AGENT
import mac_checkers


def ip_info(ip_add):
    ''' Check ip in ipinfo.io api '''
    req = urllib.request.Request(f'https://ipinfo.io/widget/{ip_add}')
    req.add_header('Authorization', f'Bearer {IPINFO_TOKEN}')
    req.add_header('Accept', 'application/json')
    req.add_header('Referer', 'https://ipinfo.io/')

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            resp = response.read().decode('utf-8')
    except urllib.error.HTTPError:
        resp = '[!] Enter correct ip address'
    return resp


def check_host(method, my_host):
    ''' Country names '''

    def countryes(i):
        return {'ae': 'UAE, Dubai',
            'at': 'Austria',
            'br': 'Brazil',
            'bg': 'Bulgaria',
            'cz': 'Czechia',
            'fi': 'Finland',
            'fr': 'France',
            'de': 'Germany',
            'hk': 'Hong Kong',
            'in': 'India',
            'ir': 'Iran',
            'il': 'Israel',
            'it': 'Italy',
            'kz': 'Kazakhstan',
            'lt': 'Lithuania',
            'md': 'Moldova',
            'nl': 'Netherlands',
            'pl': 'Poland',
            'pt': 'Portugal',
            'ru': 'Russia',
            'rs': 'Serbia',
            'ch': 'Switzerland',
            'th': 'Thailand',
            'tr': 'Turkey',
            'ua': 'Ukraine',
            'uk': 'UK',
            'us': 'USA'
            }.get(i)


    def request_check_host(url):
        req = urllib.request.Request(url)
        req.add_header('Accept', 'application/json')
        req.add_header('User-Agent', UESR_AGENT)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8')

    url = f'https://check-host.net/check-{method}?host={my_host}/&max_nodes=MAX_NODES'
    request_id = request_check_host(url)
    request_id = json.loads(request_id)['request_id']
    print('[*] Checking in progress, please wait 5 seconds ...')
    time.sleep(5)
    url = f'https://check-host.net/check-result/{request_id}'
    response = request_check_host(url)
    response = json.loads(response)
    result_list = []
    for country_abbr in response:
        country = countryes(country_abbr[0:2])
        try:
            status = response[country_abbr][0]
            result_list.append({country: status})
        except (TypeError, KeyError):
            result_list.append({country: 'None'})
    return result_list


def mac_info(mac_add):
    ''' check mac in api.macaddress.io api '''
    url = 'https://api.macaddress.io/v1?apiKey=at_LrqIc08FBOoDEsOZpGaZOIOk5UmWN&output=json&search='
    req = urllib.request.Request(url + mac_add)
    req.add_header('Accept', '*/*')
    results = []
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            resp = response.read(1024).decode('utf-8')
            vendor = resp.replace(',"', ',\n"')
            results.append(json.loads(vendor))
    except urllib.error.HTTPError:
        return '[!]Invalid request'
    res1 = mac_checkers.mac_geolocation_1(mac_add)
    res2 = mac_checkers.mac_geolocation_2(mac_add)
    if res1 is not None:
        results.append(res1)
    if res2 is not None:
        results.append(res2)
    return results


class VirusTotal():
    ''' To connect to api Virus Total '''
    def __init__(self, *args):
        ''' Check ip in Virus Total api '''
        self.headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_TOKEN,
            "content-type": "application/x-www-form-urlencoded"
        }
        data = None if len(args) == 1 else f"url={args[1]}".encode('utf-8')
        req = urllib.request.Request(
            f'https://www.virustotal.com/api/v3/{args[0]}',
            data=data, headers=self.headers
            )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                response = response.read().decode('utf-8')
                self.response = json.loads(response)
        except urllib.error.HTTPError:
            self.response = False

    @classmethod
    def filter_warn(cls, analysis_results):
        ''' Filter, shows only danger warnings '''
        sec_alert = {}
        for i in analysis_results.items():
            results = list(i)[1]['result']
            if results not in {'clean', 'unrated'}:
                sec_alert.update({i[0]: i[1]["result"]})
        return sec_alert

    def for_domain_and_ip(self):
        ''' Outputs only common fields for requests domains and ip '''
        response = self.response['data']['attributes']
        sec_alert = self.filter_warn(response['last_analysis_results'])
        data = [{
            "Whois": response['whois'].replace('\r\n', ''),
            "Last analysis stats": response['last_analysis_stats'],
            "Security": sec_alert
            }]
        return response, data

    def domain(self):
        ''' Domain info '''
        response, data = self.for_domain_and_ip()
        results = [{
            "Last DNS records": response['last_dns_records'],
            "Registrar": response['registrar'],
            "Categories": response['categories']
            }]
        return [*results, *data]

    def ip_addresses(self):
        ''' IP info '''
        response, data = self.for_domain_and_ip()
        additionally = response['last_https_certificate']
        results = [{
            "Owner": response['as_owner'],
            "Subject": additionally['subject'],
            "Issuer": additionally['issuer'],
            "Subject alternative name": additionally['extensions']['subject_alternative_name']
        }]
        return [*results, *data]

    def urls_check(self):
        ''' Check url '''
        results_link = self.response['data']['links']['self']
        req = urllib.request.Request(results_link, headers=self.headers)
        with urllib.request.urlopen(req) as response:
            resp = response.read().decode('utf-8')
            resp = json.loads(resp)
        main = resp['data']['attributes']
        sec_alert = self.filter_warn(main['results'])
        return [{
            "Stats": main['stats'],
            "Status": main['status'],
            "Security": sec_alert
            }]
