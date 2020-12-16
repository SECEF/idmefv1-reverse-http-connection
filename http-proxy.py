#!/usr/bin/python

from __future__ import unicode_literals, absolute_import, division, print_function

import argparse
import logging
import os
import requests
import ssl
import sys

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from requests.packages.urllib3.util import ssl_

# From https://www.ssi.gouv.fr/uploads/2017/07/anssi-guide-recommandations_de_securite_relatives_a_tls-v1.2.pdf
_DEFAULT_CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-RSA-CAMELLIA256-SHA384:ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA128-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:CAMELLIA128-SHA256"

_SCHEME = 'https://'

_CONTENT_TYPE = 'text/xml'


class TLSAdapter(HTTPAdapter):
    def __init__(self, ciphers, **kwargs):
        self.ciphers = ciphers
        super(TLSAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, *pool_args, **pool_kwargs):
        # Disable SSL entirely and prevent BEAST attacks
        options = ssl_.OP_NO_SSLv2 | ssl_.OP_NO_SSLv3 | ssl_.OP_NO_COMPRESSION

        # Disable weak versions of TLS if possible
        for opt in ('OP_NO_TLSv1', 'OP_NO_TLSv1_1'):
            if hasattr(ssl, opt):
                options |= getattr(ssl, opt)

        ctx = ssl_.create_urllib3_context(ciphers=self.ciphers, cert_reqs=ssl.CERT_REQUIRED, options=options)
        self.poolmanager = PoolManager(*pool_args, ssl_context=ctx, **pool_kwargs)


def forward_messages(args):
    logger = logging.getLogger('idmef_proxy')
    headers = {
        'Content-Type': _CONTENT_TYPE,
        'Accept': _CONTENT_TYPE,
    }
    with requests.Session() as sess:
        sess.cert = (args.cert, args.key)
        sess.headers = headers
        sess.verify = args.cacert
        sess.stream = True
        sess.mount('https://', TLSAdapter(args.ciphers))

        with sess.get(args.sensor, timeout=args.timeout) as msg:
            # Not messages available at this time, this is not an error per se.
            if msg.status_code == 404:
                return 0
            msg.raise_for_status()

            with sess.post(args.manager, timeout=args.timeout,
                data=msg.iter_content(None, False)) as res:
                res.raise_for_status()
                return 0


def main():
    global _DEFAULT_CIPHERS
    global _SCHEME

    # @TODO Add support for (authentication-based) proxy servers
    parser = argparse.ArgumentParser(description="IDMEF HTTPS proxy")
    parser.add_argument('--cert', default="server.pem", required=True,
                        help="X.509 certificate file to use (in PEM format)")
    parser.add_argument('--key', default="server.key", required=True,
                        help="PKCS#1 or PKCS#8 private key (in PEM format)")
    parser.add_argument('--cacert', default="CA.pem", required=True,
                        help="File containing the concatenation of PEM-encoded "
                             "certificates for acceptable Certificate Authorities")
    parser.add_argument('--verbose', '-v', action="count", default=0,
                        help="Increase verbosity (can be repeated)")
    parser.add_argument('--sensor', required=True,
                        help="URL to the sensor's HTTPS server "
                             "(e.g. https://localhost:4433/)")
    parser.add_argument('--manager', required=True,
                        help="URL to the manager's HTTPS server "
                             "(e.g. https://localhost:4434/)")
    parser.add_argument('--timeout', default=10, type=int,
                        help="Timeout for fetch/post operations")
    parser.add_argument('--ciphers', default=_DEFAULT_CIPHERS,
                        help="OpenSSL list of acceptable ciphers")
    args = parser.parse_args()

    loglevels = [
        logging.ERROR,
        logging.WARNING,
        logging.INFO,
        logging.DEBUG,
    ]
    logging.basicConfig(level=loglevels[min(args.verbose, len(loglevels) - 1)])
    logger = logging.getLogger('http_proxy')

    if not args.sensor.startswith(_SCHEME):
        logger.error("Invalid sensor URL (should begin with '{0}')".format(_SCHEME))
        return 1

    if not args.manager.startswith(_SCHEME):
        logger.error("Invalid manager URL (should begin with '{0}".format(_SCHEME))
        return 1

    try:
        return forward_messages(args)
    except:
        logging.exception("Uncaught error:")
        return 1

if __name__ == '__main__':
    sys.exit(main())
