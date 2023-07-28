""" These are scripts that check by ip, mac, domain"""
import json
import time
import secrets
from extension import IPINFO_TOKEN, VIRUSTOTAL_TOKEN
from inquiries import Queryus


class IpInfo:
    """ Check ip in ipinfo.io api """
    __slots__ = ('url', '__headers')

    def __init__(self, ip_add):
        self.url = f'https://ipinfo.io/widget/{ip_add}'
        self.__headers = {
            'Authorization': f'Bearer {IPINFO_TOKEN}',
            'Accept': 'application/json',
            'Referer': 'https://ipinfo.io/'
        }

    def check_ip(self):
        """ Sending a request to the API """
        query = Queryus()
        response = query.send(self.url, header=self.__headers)
        return response.decode()


class HostAvailability:
    """ Checking availability in different countries of the PING, DNS, TCP, UDP connect """
    __slots__ = ('url', '__headers', 'method', 'my_host', 'query')

    def __init__(self, method, my_host):
        self.method = method
        self.my_host = my_host
        self.url = 'https://check-host.net/check-'
        self.__headers = {
            'Accept': 'application/json',
        }
        self.query = Queryus()

    def check(self):
        """ Gets the final result """
        req_id = self.request_id()
        time.sleep(10)
        url = f'{self.url}result/{req_id}'
        response = self.query.send(url, header=self.__headers)
        response = self.__my_filter(response)
        return response

    def request_id(self):
        """ sends a request for validation and gets the request ID """
        url = f'{self.url}{self.method}?host={self.my_host}/&max_nodes=MAX_NODES'
        response = self.query.send(url, header=self.__headers)
        request_id = json.loads(response.decode('utf-8'))['request_id']
        print('[*] Checking in progress, please wait 5 seconds ...')
        return request_id

    @staticmethod
    def __my_filter(response):
        """ Filter countries """
        from extension import countries

        response = json.loads(response.decode('utf-8'))
        result_list = []
        for country_abbr in response:
            country = countries.get(country_abbr[0:2])
            country = country if country else country_abbr[0:2]

            status = response[country_abbr][0]
            result_list.append({country: status})
        return tuple(result_list)


class VirusTotal:
    """ To connect to api Virus Total """
    __slots__ = ('data', 'command', 'url')

    __headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_TOKEN,
        }

    def __init__(self, *args):
        """ Created vars """
        self.data = None if len(args) <= 1 else args[1]
        self.command = args[0]
        self.url = f'https://www.virustotal.com/api/v3/{self.command}'

    def check(self):
        """ Submits a request for verification """
        query = Queryus()
        response = query.send(self.url, data=self.data, header=self.__headers)
        if response:
            response = json.loads(response.decode())
            return self.my_filter(response)
        return None

    def my_filter(self, response):
        """ Deletion of unnecessary fields from API response"""
        if self.command.split('/')[0] in {'ip_addresses', 'domains', 'files'} \
                and self.data is None:
            del response['data']['links']
            del response['data']['attributes']['last_analysis_results']
            last_analysis_stats = response['data']['attributes']['last_analysis_stats']
            del response['data']['attributes']['last_analysis_stats']
            response.update({'last_analysis_stats': last_analysis_stats})
            return response
        return response['data']['links']['self']

    def send_file(self, password):
        """ Create token, headers, and send file for checking """
        boundary = secrets.token_hex(20)
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        boundary = boundary.encode()
        headers.update(self.__headers)
        data = self.__multipart_file(boundary, self.data, password)
        query = Queryus()
        response = query.send(self.url, data=data, header=headers)
        if response:
            response = json.loads(response.decode())
            return self.my_filter(response)
        return None

    def post_data(self, password=None):
        """ Sending data via API: if file or url """
        if self.command == 'urls':
            response = self.check()
        else:
            response = self.send_file(password)
        if response:
            return self.__check_results(response)
        return None

    @classmethod
    def __check_results(cls, url):
        """ Check post data """
        print('\n[*] It is scanning, please wait ...')
        time.sleep(10)
        query = Queryus()
        response = query.send(url, header=cls.__headers)
        response = json.loads(response.decode())
        if response is None:
            return None
        while response['data']['attributes']['status'] == 'queued':
            print('[*] Wait, not verified yet ...')
            time.sleep(10)
            response = query.send(url, header=cls.__headers)
            response = json.loads(response.decode())

        del response['data']['attributes']['results']
        del response['data']['links']
        del response['data']['id']
        return response

    @staticmethod
    def __multipart_file(boundary, data, password):
        """ Create multipart data """
        with open(data, "rb") as my_file:
            my_file = my_file.read()
        data = [
            b'--', boundary, b'\nContent-Disposition: form-data; name="file"; filename="',
            data.encode(), b'"\nContent-Type: text/x-python\n\n', my_file, b'\n--', boundary,
            b'--']

        if password:
            password = password.encode()
            password = (b'--', boundary, b'\nContent-Disposition: form-data; name="password"\n\n',
                        password, b'\n')

            password = b''.join(password)
            data = b''.join(data)
            return password + data
        return b''.join(data)
