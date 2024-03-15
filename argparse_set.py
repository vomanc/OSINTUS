# Setting options for the program
import argparse


VERSION = '2.2'
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
    '-url',
    type=str,
    metavar='',
    help='Virus Total, get a URL analysis report (-url example.com)'
)
parser.add_argument(
    '-d',
    type=str,
    metavar='',
    help='Dearch for information about a domain (-d example.com)'
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
    help='TCP check (-tcp example.com[:PORT])'
)
parser.add_argument(
    '-udp',
    type=str,
    metavar='',
    help='UDP check (-udp example.com[:PORT])'
)
parser.add_argument(
    '-ping',
    type=str,
    metavar='',
    help='Send ping (-ping 1.1.1.1[:PORT])'
)
parser.add_argument(
    '-dns',
    type=str,
    metavar='',
    help='(-dns example.com)'
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


def argument():
    """ Returns only existing arguments, except if not a file """
    args = parser.parse_args()
    for i in vars(args).items():
        if i[1]:
            if i[0] == 'f':
                return i[0], i[1], args.passwd
            return i
    return None
