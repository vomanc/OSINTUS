# OSINT tool
# author: @vomanc
# version 2.0
import argparse
import pprint
import logging
from extension import BANNER, IPINFO_TOKEN, VIRUSTOTAL_TOKEN, COMBAIN_TKEN
from mac_checkers import MacAddress
import checkers


def init_logger():
    """ Set logger """
    logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(filename='Osintus.log', mode='a')
    filt = [
        '%(asctime)s', '%(levelname)s', '%(filename)s', '%(lineno)s',
        '%(name)s', '%(module)s', '%(message)s'
        ]
    forma = ' - '.join(filt)
    formatter = logging.Formatter(forma)
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)


def check_tokens():
    """ Checking for tokens """
    alert = '[!] You have not added a token for'
    if len(IPINFO_TOKEN) == 0:
        return f'{alert} IPINFO_TOKEN'
    if len(VIRUSTOTAL_TOKEN) == 0:
        return f'{alert} VIRUSTOTAL_TOKEN'
    if len(COMBAIN_TKEN) == 0:
        return f'{alert} COMBAIN_TKEN'
    return True


def argument_parser():
    """ Setting options for the program  """
    parser = argparse.ArgumentParser(
        prog=f'Osintus, version: {VERSION}',
        description='OSINT',
    )
    parser.add_argument(
        '-ip',
        type=str,
        metavar='',
        help='Search for IP information (-ip: 1.1.1.1)'
    )
    parser.add_argument(
        '-ipv',
        type=str,
        metavar='',
        help='Virus Total, get information about ip addres (-ipv 1.1.1.1)'
    )
    parser.add_argument(
        '-d',
        type=str,
        metavar='',
        help='Dearch for information about a domain (-d example.com)'
    )
    parser.add_argument(
        '-url',
        type=str,
        metavar='',
        help='Virus Total, get a URL analysis report (-url example.com)'
    )
    parser.add_argument(
        '-mac',
        type=str,
        metavar='',
        help='Identify device by mac address (-mac ff:ff:ff:ff:ff:ff)'
    )
    parser.add_argument(
        '-tcp',
        type=str,
        metavar='',
        help='TCP check (-tcp example.com)'
    )
    parser.add_argument(
        '-udp',
        type=str,
        metavar='',
        help='UDP check (-udp example.com)'
    )
    parser.add_argument(
        '-dns',
        type=str,
        metavar='',
        help='(-dns example.com)'
    )
    parser.add_argument(
        '-p', '-ping',
        type=str,
        metavar='',
        help='Send ping (-p 1.1.1.1)'
    )
    parser.add_argument(
        '-http',
        metavar='',
        type=str,
        help='HTTP check (-c example.com)'
    )
    parser.add_argument(
        '-hash',
        metavar='',
        type=str,
        help='Search for a hash (-hash 5b89935c5f65f0433f754863de828044)',
    )
    parser.add_argument(
        '-f',
        type=str,
        metavar='PATH {--passwd }',
        help='Analyse suspicious files (-f /home/kali/test.txt). '
             'If it is a password protected file enter a arg {--passwd}'
    )
    parser.add_argument(
        '--passwd',
        type=str,
        metavar='',
        help='Password for files {--passwd my_password}'
    )
    parser.add_argument(
        '-v', '-version',
        action='version', version=f'Osintus, version: {VERSION}',
        help='Print version number'
    )
    return parser.parse_args()


def main(vals):
    """ Main function that starts the program """
    res = None
    if vals.ip:
        res = checkers.IpInfo(vals.ip)
        res = res.check_ip()
        print(res)
        res = None
    elif vals.ipv:
        vtapi = checkers.VirusTotal(f'ip_addresses/{vals.ipv}')
        res = vtapi.check()
    elif vals.d:
        vtapi = checkers.VirusTotal(f'domains/{vals.d}')
        res = vtapi.check()
    elif vals.url:
        vtapi = checkers.VirusTotal('urls', f"url={vals.url}".encode('utf-8'))
        res = vtapi.post_data()
    elif vals.hash:
        vtapi = checkers.VirusTotal(f'files/{vals.hash}')
        res = vtapi.check()
    elif vals.f:
        vtapi = checkers.VirusTotal('files', vals.f)
        res = vtapi.post_data(vals.passwd)
        if res is None:
            print('[!] There must be exactly one file !')
    elif vals.mac:
        mac_addr = MacAddress(vals.mac)
        res = mac_addr.checker()
    elif vals.tcp:
        query = checkers.HostAvailability('tcp', vals.tcp)
        res = query.check()
    elif vals.udp:
        query = checkers.HostAvailability('udp', vals.udp)
        res = query.check()
    elif vals.dns:
        query = checkers.HostAvailability('dns', vals.dns)
        res = query.check()
    elif vals.p:
        query = checkers.HostAvailability('ping', vals.p)
        res = query.check()
    elif vals.http:
        query = checkers.HostAvailability('http', vals.http)
        res = query.check()

    if res:
        pprint.pp(res)


if __name__ == "__main__":
    VERSION = '2.0'
    logger = logging.getLogger('app')
    print(BANNER)
    init_logger()
    logger.debug('start')
    logger.debug('Successfully wrote')
    try:
        token_status = check_tokens()
        if token_status is True:
            main(argument_parser())
        else:
            print(token_status)
    except Exception:
        logger.exception("Error message")
