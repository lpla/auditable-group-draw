import copy
import json
import unittest
from pathlib import Path

from verifier import VerificationError, verify_audit

FIXTURE = Path(__file__).parent / 'fixtures' / 'test-vector-v0.2.0.json'


class VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = json.loads(FIXTURE.read_text(encoding='utf-8'))

    def test_known_vector(self):
        result = verify_audit(copy.deepcopy(self.audit))
        self.assertEqual(result['configHash'], 'e553af800b2740338adb1377659dbecf0e36744c78baa2f024a462a8e68fa347')
        self.assertEqual(result['validCount'], 924)
        self.assertEqual(result['selectedIndex0'], 414)
        self.assertEqual(result['selectedMaskInteger'], 1818)
        self.assertEqual(result['selectionDigest'], 'a3490803162e29be1b0ecf647a413c3cb4dc03cd95b977c558b8fdbcf480d592')

    def test_tampered_seed_fails(self):
        audit = copy.deepcopy(self.audit)
        audit['seed'] = 'tampered'
        with self.assertRaises(VerificationError):
            verify_audit(audit)

    def test_tampered_assignment_fails(self):
        audit = copy.deepcopy(self.audit)
        audit['assignment'][0][0] = 'Mallory'
        with self.assertRaises(VerificationError):
            verify_audit(audit)

    def test_tampered_config_fails(self):
        audit = copy.deepcopy(self.audit)
        audit['config']['capacities'][0] = 7
        with self.assertRaises(VerificationError):
            verify_audit(audit)


if __name__ == '__main__':
    unittest.main()
