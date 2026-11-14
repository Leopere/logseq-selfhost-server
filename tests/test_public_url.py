"""Producer lease contract for generated sync URLs."""
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('tunnel_supervisor', Path(__file__).parents[1] / 'server/tunnel/supervise.py')
tunnel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tunnel)


class PublicUrlLease(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        tunnel.STATE = Path(self.directory.name) / 'public-url.json'

    def test_publishes_atomic_lease_and_clears_it(self):
        tunnel.publish('https://generated-sync.trycloudflare.com', 'a' * 32)
        value = json.loads(tunnel.STATE.read_text())
        self.assertEqual(value['url'], 'https://generated-sync.trycloudflare.com')
        self.assertEqual(value['schema'], 'logseq-public-url/v1')
        self.assertTrue(tunnel.healthy())
        self.assertFalse(tunnel.STATE.with_suffix('.tmp').exists())
        tunnel.clear_state()
        self.assertFalse(tunnel.healthy())

    def test_old_or_malformed_leases_are_not_ready(self):
        tunnel.publish('https://generated-sync.trycloudflare.com', 'a' * 32)
        original = json.loads(tunnel.STATE.read_text())
        for update in [{'updatedAt': int(time.time() * 1000) - 13000},
                       {'url': 'https://generated-sync.trycloudflare.com.evil.example'},
                       {'generation': 'invalid'}]:
            tunnel.STATE.write_text(json.dumps({**original, **update}))
            self.assertFalse(tunnel.healthy())


if __name__ == '__main__':
    unittest.main()
