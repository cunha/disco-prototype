#!/usr/bin/env python3

import argparse
import logging
import os
import resource
import sys

import ipaddress

import donna25519


def create_parser():  # {{{
    desc = '''DISCO announcement generator'''
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('--prefixes',
                        dest='prefixes',
                        metavar='LIST',
                        type=str,
                        required=True,
                        help='Comma-separated list of prefixes')
    parser.add_argument('--key-dir',
                        dest='keydir',
                        action='store',
                        metavar='DIR',
                        type=str,
                        required=False,
                        default='.',
                        help='Directory containing DISCO keys [%(default)s]')
    parser.add_argument('--logfile',
                        dest='logfile',
                        action='store',
                        metavar='FILE',
                        type=str,
                        default='generate-announcements.log',
                        help='Log file name in OUTDIR [%(default)s]')
    return parser
# }}}


def get_pubkeystr(opts):
    pubkeyfn = os.path.join(opts.keydir, 'disco-key.pub')
    privkeyfn = os.path.join(opts.keydir, 'disco-key.priv')
    logging.info('loading public key from %s', pubkeyfn)
    try:
        with open(pubkeyfn, 'rb') as fd:
            pubkey = donna25519.PublicKey(fd.read())
    except (os.error, ValueError) as e:
        logging.error('error loading public key: %s', str(e))
        logging.warning('regenerating pub/priv keys')
        privkey = donna25519.PrivateKey()
        pubkey = privkey.get_public()
        with open(pubkeyfn, 'wb') as fd:
            fd.write(pubkey.public)
            logging.warning('wrote %s', pubkeyfn)
        with open(privkeyfn, 'wb') as fd:
            fd.write(privkey.private)
            logging.warning('wrote %s', privkeyfn)
    return '0x%s' % pubkey.public.hex()


def main():
    resource.setrlimit(resource.RLIMIT_AS, (1 << 22, 1 << 22))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 30, 1 << 30))
    parser = create_parser()
    opts = parser.parse_args()
    logging.basicConfig(filename=opts.logfile,
                        format='%(message)s',
                        level=logging.DEBUG)

    message = 'announce route %s next-hop self attribute [0xff 0xe0 %s]\n'

    pubkeystr = get_pubkeystr(opts)
    logging.info('public key: %s', pubkeystr)

    prefixes = list(ipaddress.ip_network(p) for p in opts.prefixes.split(','))
    logging.info('generating announcements for %d prefixes: %s',
                 len(prefixes),
                 '\n'.join(str(p) for p in prefixes))

    for p in prefixes:
        sys.stdout.write(message % (p, pubkeystr))


if __name__ == '__main__':
    sys.exit(main())
