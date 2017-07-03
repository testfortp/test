# -*- coding: utf-8 -*-

import sys
import os


pwd = os.path.dirname(__file__)

from std.fault import Fault
import subprocess
from collections import namedtuple
import unittest
import OpenSSL
from functools import wraps
from check.check_ssl import (validate_certificate, is_expired,
                                       validate_private_key, domain_match,
                                       check_common_name)


def load_crt(self, name):
    with open(os.path.join(self.folder, name + '.crt')) as f:
        self.crt = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())

def load_key(self, name):
    with open(os.path.join(self.folder, name + '.key')) as f:
        self.key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,  f.read())

class TestSSL(unittest.TestCase):
    folder = os.path.join(pwd, 'certificates')

    def load(name, key=True, crt=True):
        def _load(func):
            @wraps(func)
            def wrapper(self, *args, **kwds):
                self.debug = False
                if crt:
                    load_crt(self, name)
                if key:
                    load_key(self, name)
                return func(self, *args, **kwds)
            return wrapper
        return _load

    @load('expired')
    def test_expired(self):
        self.assertTrue(is_expired(self.crt)[0])

    @load('ok')
    def test_expired_false(self):
        self.assertFalse(is_expired(self.crt)[0])

    @load('ok')
    def test_private_key(self):
        self.assertIsNone(validate_private_key(self))

    def test_domain_match_equal(self):
        self.assertTrue(domain_match('foo.bar.com', 'foo.bar.com'))

    def test_domain_match_wrong_simple(self):
        self.assertFalse(domain_match('foo.bar.com', 'www.foo.bar.com'))

    def test_domain_match_whildcard(self):
        self.assertTrue(domain_match('foo.bar.com', '*.bar.com'))

    def test_domain_match_whildcard_false_1(self):
        self.assertFalse(domain_match('buzz.foo.bar.com', '*.bar.com'))

    def test_domain_match_whildcard_false_2(self):
        self.assertFalse(domain_match('bar.com', '*.bar.com'))

    @load('ok')
    def test_common_name(self):
        self.assertTrue(check_common_name(self.crt, 'ok.ru'))

    @load('no_subject')
    def test_common_name_wrong(self):
        self.assertFalse(check_common_name(self.crt, 'ok.ru'))

    @load('srb', key=False)
    def test_Serbia_name(self):
        self.assertTrue(check_common_name(self.crt, 'рнидс.срб'))

    @load('srb', key=False)
    def test_Serbia_sni(self):
        self.domains_list = ['www.рнидс.срб', 'рнидс.срб']
        self.assertIsNone(validate_certificate(self))

    @load('ok')
    def test_validate_cover_all(self):
        self.domains_list = ['company.com', 'company.net']
        self.assertIsNone(validate_certificate(self))

    @load('ok')
    def test_validate_cover_not_all(self):
        self.domains_list = ['foo.company.com', 'company.net']
        with self.assertRaises(Fault):
            validate_certificate(self)


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSSL)
    unittest.TextTestRunner(verbosity=2).run(suite)
