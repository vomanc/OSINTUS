import json
from inquiries import Queryus
from extension import COMBAIN_TKEN


class MacAddress:
    """ verification of the MAC address in three resources.
    Returns information about manufacturers, geolocation """
    __slots__ = ('mac_add',)

    query = Queryus()

    def __init__(self, mac_add):
        self.mac_add = mac_add

    def checker(self):
        """ Checked all API """
        res_1 = self.__macaddress_io(self.mac_add)
        res_2 = self.__combain_com(self.mac_add)
        res_3 = self.__mylnikov(self.mac_add)
        return res_1, res_2, res_3

    @classmethod
    def __macaddress_io(cls, mac_add):
        """ Check mac method 1"""
        header = {'Accept': '*/*'}
        key = 'at_LrqIc08FBOoDEsOZpGaZOIOk5UmWN&output=json&search='
        url = f'https://api.macaddress.io/v1?apiKey={key}{mac_add}'
        response = cls.query.send(url, header)
        return json.loads(response)

    @classmethod
    def __mylnikov(cls, mac_add):
        """ Check mac method 2"""
        header = {'Accept': 'application/json'}
        url = f'http://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&bssid={mac_add}'
        response = cls.query.send(url, header)
        response = json.loads(response)
        if response['result'] == 200:
            return {'Location': response['data']}
        return None

    @classmethod
    def __combain_com(cls, mac_add):
        """ Check mac method 3 """
        url = f'https://apiv2.combain.com?key={COMBAIN_TKEN}'
        headers = {'Content-Type': 'application/json'}
        data = {
            "wifiAccessPoints": [{
                "macAddress": mac_add
            }]
        }
        data = json.dumps(data)
        data = data.encode()
        response = cls.query.send(url, data=data, header=headers)
        if response:
            response = json.loads(response)
        return response
