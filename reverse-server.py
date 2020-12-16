#!/usr/bin/python

from __future__ import unicode_literals, absolute_import, division, print_function

import argparse
import fcntl
import glob
import logging
import os
import ssl
import sys

try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from BaseHTTPServer import HTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler as BaseHTTPRequestHandler

from lxml import etree


# From https://www.ssi.gouv.fr/uploads/2017/07/anssi-guide-recommandations_de_securite_relatives_a_tls-v1.2.pdf
_DEFAULT_CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-RSA-CAMELLIA256-SHA384:ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA128-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:CAMELLIA128-SHA256"

_SPOOL_DIR = "./spool"
_MOVE_DIR = None
_DELETE = False

_CONTENT_TYPE = 'text/xml'
_ACCEPTABLE_CONTENT_TYPES = ('text/xml', 'application/xml', 'text/*', 'application/*', '*/*')
_MAX_BATCH_SIZE = -1

_EMPTY_MESSAGE = """<?xml version="1.0"?>
<idmef:IDMEF-Message xmlns:idmef="http://iana.org/idmef"/>"""

class RequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def return_error(self, code):
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, format, *args):
        logger = logging.getLogger('secef.http_server')
        logger.info("%s:%d - - [%s] %s" %
                    (self.client_address[0],
                     self.client_address[1],
                     self.log_date_time_string(),
                     format % args))

    def do_HEAD(self):
        return self.return_error(405) # Method not allowed

    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD

    def do_GET(self):
        global _CONTENT_TYPE
        global _SPOOL_DIR
        global _MOVE_DIR
        global _DELETE
        global _EMPTY_MESSAGE
        global _ACCEPTABLE_CONTENT_TYPES

        logger = logging.getLogger('secef.processor')

        if self.path != '/':
            return self.return_error(404) # Not found

        # Parse the 'Accept' header, eg.
        # "text/html, application/xhtml+xml, application/xml;q=0.9, image/webp, */*;q=0.8"
        accepted = [
            v.partition(';')[0].strip()
            for v in self.headers.get_all('accept', '*/*')[0].split(',')
        ]
        for acceptable in _ACCEPTABLE_CONTENT_TYPES:
            if acceptable in accepted:
                break
        else:
            return self.return_error(406) # Not acceptable

        parser = etree.XMLParser(load_dtd=False)
        messages = etree.fromstring(_EMPTY_MESSAGE, parser=parser)

        spool_pattern = os.path.join(_SPOOL_DIR, '*.xml')
        logger.debug("Looking for messages matching '%s'", spool_pattern)
        files = glob.iglob(spool_pattern)

        nb_files = 0
        for f in files:
           logger.debug("Retrieving content from '%s'", f)
           with open(f, 'rb') as fd:
               try:
                   fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
               except OSError:
                   # The file is probably still being created (written to),
                   # skip it for now.
                   logger.debug("Could not lock '%s', skipping for now", f)
                   continue

               try:
                   idmef = etree.parse(fd, parser=parser)
               except:
                   logger.error("Could not parser '%s'", f, exc_info=True)
                   continue
               finally:
                   moved = False
                   if _MOVE_DIR:
                       try:
                           os.rename(f, os.path.join(_MOVE_DIR, os.path.basename(f)))
                           moved = True
                       except OSError:
                           logger.warning("Could not move '%(src)s' to '%(dst)'",
                                          {'src': f, 'dst': _MOVE_DIR}, exc_info=True)
                   if _DELETE and not moved:
                       try:
                           os.unlink(f)
                       except OSError:
                           logger.warning("Could not delete '%s'", f, exc_info=True)
                   try:
                       fcntl.flock(fd, fcntl.LOCK_UN | fcntl.LOCK_NB)
                   except OSError:
                       logger.warning("Could not unlock '%s', this should never happend...",
                                      f, exc_info=True)
                       pass

           root = idmef.getroot()
           logger.debug("Found %(count)d message(s) inside '%(file)s'",
                        {"count": len(root), "file": f})
           messages.extend(root.iterchildren())
           nb_files += 1
           if _MAX_BATCH_SIZE > 0 and nb_files > _MAX_BATCH_SIZE:
               break

        logger.debug("Processed %d file(s)", nb_files)
        if not len(messages):
           return self.return_error(404) # Not found

        result = etree.tostring(messages, encoding="utf-8", xml_declaration=True)
        logger.info("Sending %(count)d message(s) to %(client)s",
                    {"count": len(messages), "client": "%s:%s" % self.client_address})

        self.send_response(200)
        self.send_header('Content-Type', _CONTENT_TYPE + '; charset=UTF-8')
        self.send_header('Content-Length', str(len(result)))
        self.end_headers()
        self.wfile.write(result)

    def version_string(self):
        return ''

def main():
    global _SPOOL_DIR
    global _MOVE_DIR
    global _DEFAULT_CIPHERS
    global _MAX_BATCH_SIZE
    global _DELETE

    parser = argparse.ArgumentParser(description="Reverse IDMEF web gateway")
    parser.add_argument('--cert', default="server.pem", required=True,
                        help="X.509 certificate file to use (in PEM format)")
    parser.add_argument('--key', default="server.key", required=True,
                        help="PKCS#1 or PKCS#8 private key (in PEM format)")
    parser.add_argument('--cacert', default="CA.pem", required=True,
                        help="File containing the concatenation of PEM-encoded "
                             "certificates for acceptable Certificate Authorities")
    parser.add_argument('--verbose', '-v', action="count", default=0,
                        help="Increase verbosity (can be repeated)")
    parser.add_argument('--address', default="0.0.0.0",
                        help="IP address to listen on")
    parser.add_argument('--port', '-p', default=3128, type=int,
                        help="TCP port to listen on (0 = select random port)")
    parser.add_argument('--ciphers', default=_DEFAULT_CIPHERS,
                        help="OpenSSL list of acceptable ciphers")
    parser.add_argument('--spooldir', default=_SPOOL_DIR,
                        help="Spooling directory where IDMEF messages (*.xml files) are read from")
    parser.add_argument('--movedir', default=_MOVE_DIR,
                        help="Directory where messages are moved to after being handled once")
    parser.add_argument('--delete', default=_DELETE, action="store_true",
                        help="Delete messages are they have been handled once")
    parser.add_argument('--maxbatchsize', '-m', default=_MAX_BATCH_SIZE,
                        help="How many files may be read from the spool directory in a single run")
    args = parser.parse_args()

    loglevels = [
        logging.ERROR,
        logging.WARNING,
        logging.INFO,
        logging.DEBUG,
    ]
    logging.basicConfig(level=loglevels[min(args.verbose, len(loglevels) - 1)])

    # Use the highest supported version of the TLS protocol.
    version = getattr(ssl, 'PROTOCOL_TLSv1_2', getattr(ssl, 'PROTOCOL_TLSv1_1', ssl.PROTOCOL_TLSv1))

    _SPOOL_DIR = args.spooldir
    _MOVE_DIR = args.movedir
    _DELETE = args.delete
    _MAX_BATCH_SIZE = args.maxbatchsize
    httpd = HTTPServer((args.address, args.port), RequestHandler)
    print("Listening on %s:%d" % httpd.server_address)

    options = dict(
        keyfile=args.key,
        certfile=args.cert,
        ca_certs=args.cacert,
        ssl_version=version,
        ciphers=args.ciphers,
        cert_reqs=ssl.CERT_REQUIRED,
        server_side=True,
    )
    try:
        httpd.socket = ssl.wrap_socket(httpd.socket, **options)
    except TypeError:
        options.pop('ciphers')
        httpd.socket = ssl.wrap_socket(httpd.socket, **options)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info('Received shutdown signal, exiting...')
        return 0

if __name__ == '__main__':
    sys.exit(main())
