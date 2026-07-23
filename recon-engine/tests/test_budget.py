import unittest
import engine.core

class TestBudget(unittest.TestCase):

    def setUp(self):
        engine.core.total_requests = 0
        engine.core.last_request_time = 0

    def test_budget_exceeded(self):
        max_req = engine.core.max_requests
        for _ in range(max_req):
            engine.core.acquire_request()

        with self.assertRaises(RuntimeError) as cm:
            engine.core.acquire_request()
        self.assertIn("Request budget exhausted", str(cm.exception))
