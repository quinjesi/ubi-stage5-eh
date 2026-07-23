import unittest
from engine.scope import Scope
from engine.core import probe_http, acquire_request, max_requests

SCOPE_PATH = "/home/sstarr/Documents/ubi-stage5-eh/lab-runtime/scope.csv"

class TestScope(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scope = Scope(SCOPE_PATH)

    def test_in_port_allowed(self):
        self.assertTrue(self.scope.is_allowed('127.0.0.1', 18231))
        self.assertTrue(self.scope.is_allowed('localhost', 23420))

    def test_out_port_denied(self):
        self.assertFalse(self.scope.is_allowed('127.0.0.1', 9999))

    def test_unlisted_port_denied(self):
        self.assertFalse(self.scope.is_allowed('127.0.0.1', 12345))

    def test_non_loopback_denied(self):
        self.assertFalse(self.scope.is_allowed('10.0.0.1', 18231))
        self.assertFalse(self.scope.is_allowed('192.168.1.1', 23420))
        self.assertFalse(self.scope.is_allowed('example.com', 18231))

    def test_probe_http_calls_guard(self):
        with self.assertRaises(PermissionError) as cm:
            probe_http('127.0.0.1', 9999, self.scope)
        self.assertIn("Scope denied", str(cm.exception))
