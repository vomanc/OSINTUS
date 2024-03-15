# OSINT tool
# author: @vomanc
# version 2.2
# https://github.com/vomanc/OSINTUS
import pprint
import logging
from extension import BANNER, IPINFO_TOKEN, VIRUSTOTAL_TOKEN, COMBAIN_TKEN
from argparse_set import argument
from mac_checkers import MacAddress
import checkers


def init_logger():
    """ Set logger """
    logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(filename='Osintus.log', mode='a')
    filters = [
        '%(asctime)s', '%(levelname)s', '%(filename)s', '%(lineno)s',
        '%(name)s', '%(module)s', '%(message)s'
        ]
    forma = ' - '.join(filters)
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


def main(args):
    """ Main function that starts the program """
    res = None
    match args[0]:
        case 'ip':
            res = checkers.IpInfo(args[1])
            res = res.check_ip()
            print(res)
            res = None
        case 'ipv':
            vtapi = checkers.VirusTotal(f'ip_addresses/{args[1]}')
            res = vtapi.check()
        case 'd':
            vtapi = checkers.VirusTotal(f'domains/{args[1]}')
            res = vtapi.check()
        case 'url':
            vtapi = checkers.VirusTotal('urls', f"url={args[1]}".encode('utf-8'))
            res = vtapi.post_data()
        case 'hash':
            vtapi = checkers.VirusTotal(f'files/{args[1]}')
            res = vtapi.check()
        case 'f':
            vtapi = checkers.VirusTotal('files', args[1])
            res = vtapi.post_data(args[2])
            if res is None:
                print('[!] There must be exactly one file !')
        case 'mac':
            mac_addr = MacAddress(args[1])
            res = mac_addr.checker()
        case 'tcp' | 'udp' | 'dns' | 'ping' | 'http':
            query = checkers.HostAvailability(args[0], args[1])
            res = query.check()
        case _:
            raise TypeError("osintus >> main >> match.case: Not a point we support")

    if res:
        pprint.pp(res)


if __name__ == "__main__":
    logger = logging.getLogger('app')
    print(BANNER)
    init_logger()
    logger.debug('start')
    logger.debug('Successfully wrote')
    try:
        token_status = check_tokens()
        if token_status is True:
            main(argument())
        else:
            print(token_status)
    except Exception:
        logger.exception("Error message")
