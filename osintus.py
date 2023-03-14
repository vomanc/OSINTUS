""" OSINT tool
    author: @vomanc
    version 1.1
"""
import argparse
import pprint
import logging
from extension import BANNER, IPINFO_TOKEN, VIRUSTOTAL_TOKEN, COMBAIN_TKEN
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
        print(f'{alert} IPINFO_TOKEN')
    if len(VIRUSTOTAL_TOKEN) == 0:
        print(f'{alert} VIRUSTOTAL_TOKEN')
    if len(COMBAIN_TKEN) == 0:
        print(f'{alert} COMBAIN_TKEN')


def argument_parser():
    """ Setting options for the program  """
    parser = argparse.ArgumentParser(
        prog=f'Osintus, version: {VERSION}',
        description='OSINT',
        add_help=True
    )
    parser.add_argument(
        '-ip',
        type=str,
        help='Search for IP information [-ip: 1.1.1.1]'
    )
    parser.add_argument(
        '-ipv',
        type=str,
        help='Virus Total, get information about ip addres [-ipv 1.1.1.1]'
    )
    parser.add_argument(
        '-d',
        type=str,
        help='Dearch for information about a domain [-d example.com]'
    )
    parser.add_argument(
        '-url',
        type=str,
        help='Virus Total, get a URL analysis report [-url example.com]'
    )
    parser.add_argument(
        '-mac',
        type=str,
        help='Identify device by mac address [-mac ff:ff:ff:ff:ff:ff]'
    )
    parser.add_argument(
        '-tcp',
        type=str,
        help='TCP check [-tcp example.com]'
    )
    parser.add_argument(
        '-udp',
        type=str,
        help='UDP check [-udp example.com]'
    )
    parser.add_argument(
        '-dns',
        type=str,
        help='[-dns example.com]'
    )
    parser.add_argument(
        '-p',
        type=str,
        help='Send ping [-p 1.1.1.1]'
    )
    parser.add_argument(
        '-http',
        type=str,
        help='HTTP check [-c example.com]'
    )
    parser.add_argument(
        '-v', '-version',
        action='version', version=f'Osintus, version: {VERSION}',
        help='Print version number'
    )

    return parser


def main(parser):
    """ Main function that starts the program """
    args = parser.parse_args()
    alert = '[!]Invalid request'

    if args.ip is not None:
        print(checkers.ip_info(args.ip))
    elif args.ipv is not None:
        vtapi = checkers.VirusTotal(f'ip_addresses/{args.ipv}')
        ip_check = vtapi.ip_addresses() if vtapi.response is not False else alert
        pprint.pprint(ip_check)
    elif args.d is not None:
        vtapi = checkers.VirusTotal(f'domains/{args.d}')
        domain = vtapi.domain() if vtapi.response is not False else alert
        pprint.pprint(domain)
    elif args.url is not None:
        vtapi = checkers.VirusTotal('urls', args.url)
        url = vtapi.urls_check() if vtapi.response is not False else alert
        pprint.pprint(url)
    elif args.mac is not None:
        pprint.pprint(checkers.mac_info(args.mac))
    elif args.tcp is not None:
        pprint.pprint(checkers.check_host('tcp', args.tcp))
    elif args.udp is not None:
        pprint.pprint(checkers.check_host('udp', args.udp))
    elif args.dns is not None:
        pprint.pprint(checkers.check_host('dns', args.dns))
    elif args.p is not None:
        pprint.pprint(checkers.check_host('ping', args.p))
    elif args.http is not None:
        pprint.pprint(checkers.check_host('http', args.http))


if __name__ == "__main__":
    VERSION = '1.1'
    logger = logging.getLogger('app')
    print(BANNER)
    init_logger()
    logger.debug('start')
    logger.debug('Successfully wrote')
    check_tokens()

    try:
        main(argument_parser())
    except Exception:
        logger.exception("Error message")
