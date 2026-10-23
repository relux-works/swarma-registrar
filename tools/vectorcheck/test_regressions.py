"""Signed neighbor fixtures for checker guards, separate from Appendix B inventory."""
import json
from pathlib import Path
import unittest

import check


class CheckerRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        cls.fixtures = Path(__file__).resolve().parent / 'fixtures'
        cls.seeds = json.loads((root / 'vectors/keys/seeds.json').read_text())
        check.verify_test_keys(root / 'vectors', cls.seeds)
        expected = {
            'media-json', 'media-charset', 'media-charset-case',
            'media-type-space', 'media-subtype-space',
            'leading-hyphen-enrollment', 'leading-hyphen-registration',
            'explicit-structured-invalid', 'enrollment-overlength', 'registration-overlength',
        }
        if {path.stem for path in cls.fixtures.glob('*.json')} != expected:
            raise AssertionError('regression fixture inventory differs from exercised cases')

    def verify_fixtures(self, *names):
        for name in names:
            with self.subTest(fixture=name):
                vector = check.parse((self.fixtures / (name + '.json')).read_bytes())
                try:
                    check.verify(vector, self.seeds)
                except check.Rejected as exc:
                    self.fail(f'{name}: {exc}')

    # Invalid type-token spacing refuses; plain JSON and both unquoted charset spellings accept.
    def test_media_type_token_boundaries(self):
        self.verify_fixtures('media-json', 'media-charset', 'media-charset-case',
                             'media-type-space')

    # Invalid subtype-token spacing must refuse with the same valid nearby controls.
    def test_media_subtype_token_boundaries(self):
        self.verify_fixtures('media-json', 'media-charset', 'media-charset-case',
                             'media-subtype-space')

    # Signed structured UID names accept; explicit-list grammar and mxid cap stay strict.
    def test_signed_enrollment_structured_union(self):
        self.verify_fixtures('leading-hyphen-enrollment', 'explicit-structured-invalid',
                             'enrollment-overlength')

    # Signed structured request names accept; exceeding the mxid cap still refuses.
    # The enrollment uses legacy UID names so its syntax cannot mask the request guard.
    def test_signed_registration_structured_union(self):
        self.verify_fixtures('leading-hyphen-registration', 'registration-overlength')


if __name__ == '__main__':
    unittest.main()
