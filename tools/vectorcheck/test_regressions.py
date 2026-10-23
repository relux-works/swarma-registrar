"""Signed neighbor fixtures for checker guards, separate from Appendix B inventory."""
import copy
import json
from pathlib import Path
import unittest

import check


class CheckerRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        cls.vector_root = root / 'vectors'
        cls.fixtures = Path(__file__).resolve().parent / 'fixtures'
        cls.seeds = json.loads((root / 'vectors/keys/seeds.json').read_text())
        check.verify_test_keys(root / 'vectors', cls.seeds)
        expected = {
            'media-json', 'media-charset', 'media-charset-case',
            'media-type-space', 'media-subtype-space',
            'media-semicolon-ows',
            'media-field-ows',
            'media-combined-ows',
            'media-quoted-charset',
            'media-quoted-charset-case',
            'media-equals-space',
            'media-equals-left-space',
            'media-equals-right-tab',
            'media-charset-name-space',
            'media-charset-value-space',
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

    def verify_rows(self, *rows):
        for row in rows:
            with self.subTest(row=row):
                domain = 'enrollment-1' if row.startswith(('E', 'PE')) else 'registration-1'
                group = '1-positive' if row.startswith('P') else '0-negative'
                vector = check.parse((self.vector_root / domain / group / (row + '.json')).read_bytes())
                try:
                    check.verify(vector, self.seeds)
                except check.Rejected as exc:
                    self.fail(f'{row}: {exc}')

    # These rows retain their deciding nonce/budget rule while legitimate signed
    # prefixes build both kinds of accounting; no private state is installed.
    def test_reachable_accounting_traces(self):
        self.verify_rows('R83', 'R84', 'R86', 'R87', 'R111', 'R129', 'PR13', 'PR14', 'PR18')

    def reachable_row(self, row):
        group = '1-positive' if row.startswith('P') else '0-negative'
        return check.parse((self.vector_root / 'registration-1' / group / (row+'.json')).read_bytes())

    # Removing a genuine prefix must not be silently replaced by seeded state.
    def test_reachable_prefix_required(self):
        vector = self.reachable_row('R83')
        check.verify(vector, self.seeds)
        broken = copy.deepcopy(vector)
        broken['before'] = []
        with self.assertRaisesRegex(check.Rejected, 'outcome disagreement: computed accept, stored nonce_replayed'):
            check.verify(broken, self.seeds)

    # Erasing the explicit clocks loses the exact 60-second pruning boundary.
    def test_reachable_trace_clock_required(self):
        vector = self.reachable_row('PR13')
        check.verify(vector, self.seeds)
        broken = copy.deepcopy(vector)
        for step in broken['before']:
            del step['monotonic_now']
        with self.assertRaisesRegex(check.Rejected, 'outcome disagreement: computed rate_limited, stored accept'):
            check.verify(broken, self.seeds)

    # A declared monotonic trace may not move backward; healthy forward controls
    # above still traverse real signature, authority and accounting checks.
    def test_reachable_trace_clock_regression(self):
        vector = self.reachable_row('PR13')
        check.verify(vector, self.seeds)
        broken = copy.deepcopy(vector)
        broken['before'][0]['monotonic_now'] = 1
        broken['before'][1]['monotonic_now'] = 0
        with self.assertRaisesRegex(check.Rejected, 'trace monotonic time must not regress'):
            check.verify(broken, self.seeds)

    # R111 succeeds at the original release instant; the same fresh proof one
    # monotonic second earlier still refuses. This pins time, not a retry bypass.
    def test_reachable_release_boundary(self):
        vector = self.reachable_row('R111')
        check.verify(vector, self.seeds)
        broken = copy.deepcopy(vector)
        broken['after'][0]['monotonic_now'] = 60
        with self.assertRaisesRegex(check.Rejected, 'outcome disagreement: computed rate_limited, stored accept'):
            check.verify(broken, self.seeds)

    # New planned headers carry their exact token witnesses and ordered outcomes/state.
    def test_planned_media_token_boundaries(self):
        self.verify_rows('PR1', 'PR30', 'R136', 'R137')

    # The adopted media rows pin exact quoted, assignment and OWS witnesses.
    def test_planned_media_ruling(self):
        self.verify_rows('PR31', 'PR32', 'PR33', 'R138', 'R139')

    # SP/HTAB around separators/fields accept; either side of '=' still refuses
    # with no JWT or accounting change, using otherwise identical signed bodies.
    def test_media_ows_boundaries(self):
        self.verify_fixtures('media-json', 'media-charset', 'media-semicolon-ows',
                             'media-field-ows', 'media-combined-ows', 'media-equals-space',
                             'media-equals-left-space', 'media-equals-right-tab')

    # Unquoted charset tokens accept; quoting either case refuses with no JWT,
    # no reservation/debit and unchanged authority, as the §6 narrowing requires.
    def test_media_unquoted_charset(self):
        self.verify_fixtures('media-charset', 'media-charset-case',
                             'media-quoted-charset', 'media-quoted-charset-case')

    # Parameter tokens cannot contain whitespace, alongside a valid unquoted control.
    def test_media_parameter_tokens(self):
        self.verify_fixtures('media-charset', 'media-charset-name-space',
                             'media-charset-value-space')

    # The media predicate permits only SP/HTAB at OWS boundaries; this focused
    # check does not qualify a real HTTP parser or exercise admission state.
    def test_media_ows_is_only_sp_htab(self):
        for whitespace, supported in [(' ', True), ('\t', True), ('\r', False),
                                     ('\n', False), ('\v', False), ('\f', False),
                                     ('\u00a0', False)]:
            for header in [whitespace+'application/json'+whitespace,
                           'application/json'+whitespace+';'+whitespace+'charset=utf-8']:
                with self.subTest(header=header):
                    self.assertEqual(check.content_type_supported(header), supported)

    # Signed leading-hyphen requests cover both sides of the mxid cap and an empty role.
    def test_planned_request_name_union_and_boundaries(self):
        self.verify_rows('PR28', 'PR29', 'R134', 'R135')

    # Signed enrollment neighbors retain legacy-only explicit names and exact mxid limits.
    def test_planned_enrollment_name_union_and_boundaries(self):
        self.verify_rows('PE14', 'PE15', 'E112', 'E113', 'E114')

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
