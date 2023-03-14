"""Check mac address geolocation"""
import urllib.request
import urllib.parse
import json
from extension import COMBAIN_TKEN


def mac_geolocation_1(bssid):
    """ check mac metiod 1"""
    headers = {'Accept': 'application/json'}
    url = f'http://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&bssid={bssid}'
    req = urllib.request.Request(url, headers=headers)

    with urllib.request.urlopen(req, timeout=10) as response:
        resp = response.read().decode('utf-8')
        resp = json.loads(resp)
        if resp['result'] == 200:
            return [{'Location': resp['data']}]
        return None


def mac_geolocation_2(bssid):
    """ check mac method 2"""
    url = f'https://apiv2.combain.com?key={COMBAIN_TKEN}'
    headers = {'Content-Type': 'application/json'}
    data = {
        "wifiAccessPoints": [{
            "macAddress": bssid
        }]
    }
    data = json.dumps(data)
    data = data.encode()
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, data=data, timeout=10) as response:
            resp = response.read().decode('utf-8')
    except urllib.error.HTTPError:
        resp = None
    return resp
