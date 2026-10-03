import copy
import json
import tempfile
import unittest
from pathlib import Path

from verifier import MAX_AUDIT_BYTES, VerificationError, verify_audit, verify_file

FIXTURES = Path(__file__).parent / 'fixtures'
BASE_FIXTURE = FIXTURES / 'test-vector-v0.2.0.json'
RESTRICTED_FIXTURE = FIXTURES / 'test-vector-restricted-v0.2.0.json'


class VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = json.loads(BASE_FIXTURE.read_text(encoding='utf-8'))
        cls.restricted = json.loads(RESTRICTED_FIXTURE.read_text(encoding='utf-8'))

    def test_known_vector(self):
        result = verify_audit(copy.deepcopy(self.audit))
        self.assertEqual(result['configHash'], 'e553af800b2740338adb1377659dbecf0e36744c78baa2f024a462a8e68fa347')
        self.assertEqual(result['validCount'], 924)
        self.assertEqual(result['selectedIndex0'], 414)
        self.assertEqual(result['selectedMaskInteger'], 1818)
        self.assertEqual(result['selectionDigest'], 'a3490803162e29be1b0ecf647a413c3cb4dc03cd95b977c558b8fdbcf480d592')

    def test_restricted_unicode_vector(self):
        result = verify_audit(copy.deepcopy(self.restricted))
        self.assertEqual(result['configHash'], 'dca0a7cc447e9631a9720b7f774ee90295d7356d568a46a09fd9efe4fdc00ab4')
        self.assertEqual(result['validCount'], 8)
        self.assertEqual(result['selectedIndex0'], 3)
        self.assertEqual(result['selectedMaskInteger'], 87)
        self.assertEqual(result['selectionDigest'], '7d6c05cc247c2f8a2fb17f60a82af699de5140f98f237d87b32e8e32cb5cb2d3')

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

    def test_unknown_schema_fails_before_enumeration(self):
        audit = copy.deepcopy(self.audit)
        audit['auditSchemaVersion'] = '999'
        with self.assertRaisesRegex(VerificationError, 'unsupported audit schema'):
            verify_audit(audit)

    def test_more_than_twenty_participants_is_rejected(self):
        audit = copy.deepcopy(self.audit)
        audit['config']['names'] = [f'P{i}' for i in range(21)]
        audit['config']['fixed'] = [None] * 21
        with self.assertRaisesRegex(VerificationError, 'between 2 and 20'):
            verify_audit(audit)

    def test_extra_config_field_is_rejected(self):
        audit = copy.deepcopy(self.audit)
        audit['config']['unexpected'] = True
        with self.assertRaisesRegex(VerificationError, 'unexpected unexpected'):
            verify_audit(audit)

    def test_boolean_cannot_masquerade_as_integer(self):
        audit = copy.deepcopy(self.audit)
        audit['validCount'] = True
        with self.assertRaisesRegex(VerificationError, 'must be an integer'):
            verify_audit(audit)

    def test_reserved_separator_in_name_is_rejected(self):
        audit = copy.deepcopy(self.audit)
        audit['config']['names'][0] = 'Ana, alias'
        with self.assertRaisesRegex(VerificationError, 'reserved constraint separator'):
            verify_audit(audit)

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'duplicate.json'
            path.write_text('{"auditSchemaVersion":"2","auditSchemaVersion":"2"}', encoding='utf-8')
            with self.assertRaisesRegex(VerificationError, 'duplicate JSON object key'):
                verify_file(path)

    def test_oversized_file_is_rejected_before_json_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'huge.json'
            path.write_bytes(b' ' * (MAX_AUDIT_BYTES + 1))
            with self.assertRaisesRegex(VerificationError, 'too large'):
                verify_file(path)


if __name__ == '__main__':
    unittest.main()
