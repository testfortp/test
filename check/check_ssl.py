# -*- coding: utf-8 -*-
import re
import datetime
from std.fault import Fault
from std.logger.const import *
import OpenSSL

def load_private_key(private_key, debug=False):
    ''' try to load private key '''
    try:
        return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    except Exception as err:
        if debug:
            raise
        raise Fault('Invalid private key.', 400)

def load_certificate(certificate, debug=False):
    ''' try to load certificate '''

    try:
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
    except Exception as err:
        if debug:
            raise
        raise Fault('Invalid certificate.', 400)

def domain_match(domain, ssl_domain):
    ''' check whether domains match absolutely or whildcard-way '''

    ssl_domain = ssl_domain.decode('utf-8').encode('idna')
    domain = domain.decode('utf-8').encode('idna')
    if ssl_domain.startswith('*'):  # whildcard certificate
        if domain.split('.')[1:] == ssl_domain.split('.')[1:]:  # one level only
            return True

    return domain == ssl_domain

def check_common_name(certificate, domain, debug=False):
    ''' check whether domain is covered in Subject Common Name (CN) field '''

    if isinstance(certificate, basestring):
        certificate = load_certificate(certificate, debug=debug)

    subject = certificate.get_subject()
    common_name = [b for a, b in subject.get_components() if a == 'CN']
    if not common_name:
        return False
    common_name = common_name[0]
    is_match = domain_match(domain, common_name)

    return is_match

def is_expired(certificate, debug=False):
    ''' check whether certificate is expired '''

    if isinstance(certificate, basestring):
        certificate = load_certificate(certificate, debug=debug)

    time_string = certificate.get_notAfter()
    not_after = datetime.datetime.strptime(time_string, "%Y%m%d%H%M%SZ")

    time_string = certificate.get_notBefore()
    not_before = datetime.datetime.strptime(time_string, "%Y%m%d%H%M%SZ")

    now = datetime.datetime.utcnow()
    too_early = not_before > now
    too_late = now > not_after
    is_really_expired = too_early or too_late

    return is_really_expired, not_after

def validate_certificate(self):
    ''' check whether all request domains are signed by request certificate '''

    certificate = self.crt
    domains = self.domains_list
    if isinstance(certificate, basestring):
        certificate = load_certificate(certificate, debug=self.debug)

    expired, not_after = is_expired(certificate, debug=self.debug)
    if expired:
        raise Fault('Certificate has expired (not after {0})'.format(str(not_after)), 400)
    self.not_after = not_after

    # check whether all domains are signed
    for i in xrange(certificate.get_extension_count()):
        extension = certificate.get_extension(i)
        if extension.get_short_name() == 'subjectAltName':
            ssl_domains = re.findall('(?<=DNS:)[^ ,]+', str(extension), re.UNICODE)
            for domain in domains:
                if isinstance(domain, unicode):
                    domain = domain.encode('utf-8')
                if not any(domain_match(domain, ssl_domain) for ssl_domain in ssl_domains):
                    if not check_common_name(certificate, domain, debug=self.debug):
                        raise Fault(u'Domain "{0}" is not signed by certificate'.format(domain.decode('utf-8')), 400)

def validate_private_key(self):
    ''' check whether private_key matches certificate '''

    certificate = self.crt
    private_key = self.key
    if isinstance(certificate, basestring):
        certificate = load_certificate(certificate, debug=self.debug)

    if isinstance(private_key, basestring):
        private_key = load_private_key(private_key, debug=self.debug)

    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_privatekey(private_key)
    context.use_certificate(certificate)
    try:
        context.check_privatekey()
    except OpenSSL.SSL.Error:
        if self.debug:
            raise
        raise Fault('Private key does not match certificate.', 400)
