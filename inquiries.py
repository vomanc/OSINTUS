# Inquiries allows you to send HTTP/1.1 requests
# Written in pure python
# Author: @vomanc
# This module works partially and is in the process of development
# If a "data" is specified, a POST request will be sent automatically
# You can send a request
# Supports HTTP and HTTPS proxies
# Send files in binary form
# Version 1.0
import urllib.request
import urllib.error


class Queryus:
    """ Sends requests and processes responses """
    __slots__ = ('status',)

    def __init__(self):
        self.status = None

    def send(self, url: str, header: dict = None, data: bytes = None, proxy=None):
        """ Sends a request to the specified link. 'data' takes in bits.
         If 'data' is specified, sends a POST request
         """
        header = self.__header(header)
        request = urllib.request.Request(url, data=data, headers=header)
        if proxy:
            proxy = proxy.split('://')
            request.set_proxy(proxy[1], proxy[0])
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                self.status = response.status
                return response.read()
        except urllib.error.HTTPError:
            return None

    @classmethod
    def __header(cls, header: dict) -> dict:
        """ Query header setting """
        data = {
            'User-Agent': 'Python-Inquiries/1.0',
            # 'Accept-Encoding': 'gzip, deflate, br'
        }
        if header:
            data.update(header)
        return data
