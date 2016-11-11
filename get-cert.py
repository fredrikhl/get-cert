#!/usr/bin/env python
# encoding: utf-8
""" Fetch remote server certificate. """
from __future__ import print_function, unicode_literals

import ssl
import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def HostPortType(argument):
    parts = argument.split(':')
    host = parts[0]
    port = 443 if len(parts) == 1 else int(parts[1])
    # TODO: Validate and handle errors
    return (host, port)


def get_certificate(hostname_or_ip, port):
    return ssl.get_server_certificate((hostname_or_ip, port))


class CertificateInfo(object):

    def __init__(self, pem):
        self.__pem = pem

    @property
    def certificate(self):
        try:
            return self.__crt
        except AttributeError:
            backend = default_backend()
            self.__crt = x509.load_pem_x509_certificate(
                self.pem.encode('ascii'), backend)
            return self.__crt

    @property
    def pem(self):
        return self.__pem

    @staticmethod
    def __get_name_oid_value(name, attribute):
        return [attr.value for attr in name.get_attributes_for_oid(attribute)]

    @property
    def cn(self):
        cns = self.__get_name_oid_value(self.certificate.subject,
                                        x509.OID_COMMON_NAME)
        return cns[0]

    def match_hostname(self, hostname):
        raise NotImplementedError()
        # We need a dict-like representation, like SSLSocket.getpeercert()
        # returns
        return ssl.match_hostname(None, hostname)


def match_hostname_action(hostname, ci):
    ci.match_hostname(hostname)
    print("Hostname: {!s}".format(hostname))
    print("CN: {!s}".format(ci.cn))


def main(args=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-h', '--host', type=str, default='localhost')
    parser.add_argument('-p', '--port', type=int, default=443)
    args = parser.parse_args(args)

    cert = get_certificate(args.host, args.port)
    ci = CertificateInfo(cert)

    print(ci.pem)


if __name__ == '__main__':
    main()
