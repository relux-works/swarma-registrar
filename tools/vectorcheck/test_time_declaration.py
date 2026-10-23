"""Declaration and startup-plan checks; no provider or monotonic-hold execution."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import check


class TimeDeclarationRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        cls.root = root
        cls.spec = (root / 'spec/registrar.md').read_text()
        cls.vectors = [check.parse(path.read_bytes())
                       for path in sorted((root / 'vectors').glob('*/*/*.json'))]
        cls.rows = {vector['row'] for vector in cls.vectors}

    def replace_declaration(self, rows):
        lines = self.spec.splitlines()
        index = next(i for i, line in enumerate(lines)
                     if line.startswith('<!-- abstract-post-hold-rows-v1: '))
        lines[index] = '<!-- abstract-post-hold-rows-v1: ' + json.dumps(sorted(rows)) + ' -->'
        return '\n'.join(lines)

    def verify(self, spec=None, vectors=None):
        check.verify_time_declaration(self.spec if spec is None else spec,
                                      self.vectors if vectors is None else vectors,
                                      self.rows)

    # Each direction of equality rejects the named mismatch; the real inventory passes.
    def test_undeclared_clock_row(self):
        with self.assertRaisesRegex(check.Rejected, 'undeclared clock fixture rows: R124'):
            self.verify(spec=self.replace_declaration(self.rows - {'R124'}))
        self.verify()

    def test_declared_row_without_clock_fields(self):
        vectors = copy.deepcopy(self.vectors)
        vector = next(v for v in vectors if v['row'] == 'PR1')
        for field in ('actual_start_millis', 'start_barrier', 'startup_verified',
                      'clock_healthy', 'clock_fenced'):
            del vector['fixture'][field]
        with self.assertRaisesRegex(check.Rejected, 'declared rows without clock fixture fields: PR1'):
            self.verify(vectors=vectors)
        self.verify()

    # Presence, including false values and scheduled clock/restart inputs, defines membership.
    def test_clock_field_presence(self):
        for field in ('actual_start_millis', 'start_barrier', 'startup_verified',
                      'clock_healthy', 'clock_fenced'):
            for location in ('fixture', 'before', 'after'):
                with self.subTest(field=field, location=location):
                    vector = {'row': 'PR1', 'fixture': {}, 'before': [], 'after': []}
                    item = {field: False}
                    if location == 'fixture':
                        vector[location] = item
                    else:
                        vector[location] = [dict(item, event='restart')]
                    self.assertEqual(check.clock_fixture_rows([vector]), {'PR1'})
        vector = {'row': 'PR1', 'fixture': {'now': 1, 'healthy': True},
                  'before': [{'event': 'clock', 'healthy': False}]}
        self.assertEqual(check.clock_fixture_rows([vector]), {'PR1'})
        vector['before'] = [{'event': 'audit', 'healthy': False}]
        self.assertEqual(check.clock_fixture_rows([vector]), set())

    # Missing/duplicated/malformed declarations fail rather than silently selecting one.
    def test_declaration_shape(self):
        line = next(line for line in self.spec.splitlines()
                    if line.startswith('<!-- abstract-post-hold-rows-v1: '))
        for replacement in ('', line + '\n' + line,
                            '<!-- abstract-post-hold-rows-v1: ["PR1", "PR1"] -->',
                            '<!-- abstract-post-hold-rows-v1: {"PR1": true} -->',
                            '<!-- abstract-post-hold-rows-v1: [ -->',
                            '<!-- abstract-post-hold-rows-v1: [1] -->'):
            with self.subTest(replacement=replacement[:50]):
                with self.assertRaisesRegex(check.Rejected, 'abstract post-hold declaration'):
                    self.verify(spec=self.spec.replace(line, replacement))
        self.verify()

    # All four negative hold witnesses and their PT controls must remain in B.3.
    def test_required_negative_hold_rows(self):
        for row in ('T1', 'T2', 'T3', 'T4'):
            with self.subTest(row=row):
                spec = '\n'.join(line for line in self.spec.splitlines()
                                 if not line.startswith('| ' + row + ' |'))
                with self.assertRaisesRegex(check.Rejected, 'missing negative startup hold rows: ' + row):
                    self.verify(spec=spec)
        self.verify()

    # Negatives cannot move behind positives, and duplicate/malformed plan rows fail.
    def test_startup_plan_row_shape_and_order(self):
        t2 = next(line for line in self.spec.splitlines() if line.startswith('| T2 |'))
        pt1 = next(line for line in self.spec.splitlines() if line.startswith('| PT1 |'))
        cases = [
            (self.spec.replace(t2 + '\n', '').replace(pt1, pt1 + '\n' + t2),
             'negative startup row follows positive controls: T2'),
            (self.spec.replace(t2, t2 + '\n' + t2), 'duplicate startup plan row: T2'),
            (self.spec.replace(t2, '| T2 | PT1 |'), 'malformed startup plan row: T2'),
        ]
        for spec, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(check.Rejected, message):
                    self.verify(spec=spec)
        self.verify()

    # A missing section, unresolved PT, PR shortcut, or cyclic control cannot satisfy the plan.
    def test_startup_positive_controls_resolve(self):
        b3 = self.spec.index('### B.3 ')
        c = self.spec.index('## Appendix C.', b3)
        missing_section = self.spec[:b3] + self.spec[c:]
        pt1 = next(line for line in self.spec.splitlines() if line.startswith('| PT1 |'))
        t2 = next(line for line in self.spec.splitlines() if line.startswith('| T2 |'))
        cases = [
            (missing_section, 'missing B.3 startup plan'),
            (self.spec.replace(pt1 + '\n', ''), 'unresolved startup positive control: PT1'),
            (self.spec.replace(t2, t2.removesuffix('PT1 |') + 'PR1 |'),
             'negative startup row requires PT control: T2'),
            (self.spec.replace(pt1, pt1.removesuffix('PR1 |') + 'PT1 |'),
             'cyclic startup positive control: PT1'),
        ]
        for spec, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(check.Rejected, message):
                    self.verify(spec=spec)
        self.verify()

    def assert_cli(self, spec, code, message):
        with tempfile.TemporaryDirectory(prefix='checker-') as scratch:
            root = Path(scratch)
            (root / 'spec').mkdir()
            (root / 'spec/registrar.md').write_text(spec)
            result = subprocess.run(
                [sys.executable, '-B', str(Path(check.__file__).resolve()),
                 '--vectors', str(self.root / 'vectors')],
                cwd=root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        self.assertIn(message, result.stderr if code else result.stdout)
        if code:
            self.assertNotIn('Traceback', result.stderr)

    def marker_line(self):
        return next(line for line in self.spec.splitlines()
                    if line.startswith('<!-- abstract-post-hold-rows-v1: '))

    # Global discovery must reject a second declaration outside A; the clean CLI accepts.
    def test_cli_duplicate_marker_outside_appendix_a(self):
        self.assert_cli(self.spec + '\n' + self.marker_line() + '\n', 1,
                        'abstract post-hold declaration must occur exactly once globally')
        self.assert_cli(self.spec, 0, 'PASS: 310 declared abstract post-hold rows')

    # Malformed extra names/JSON/comment syntax must be counted before validating shape.
    def test_cli_malformed_extra_marker(self):
        for extra in ('<!-- abstract-post-hold-rows-v1: [ -->',
                      '<!-- abstract-post-hold-rows-v2: [] -->',
                      '<!-- abstract-post-hold-row-v1: [] -->',
                      '<!-- abstract-post-hold: [] -->',
                      '<!-- ABSTRACT-POST-HOLD-ROWS-V1: [] -->',
                      '<!-- abstract_post_hold_rows_v1: [] -->',
                      '<!-- abstract post hold rows v1: [] -->',
                      'prefix abstract-post-hold-rows-v1 []'):
            with self.subTest(extra=extra):
                self.assert_cli(self.spec + '\n' + extra + '\n', 1,
                                'abstract post-hold declaration must occur exactly once globally')
        self.assert_cli(self.spec, 0, 'PASS: 310 declared abstract post-hold rows')

    # Indentation cannot hide a competing in-A marker, including Markdown code indentation.
    def test_cli_indented_duplicate_marker(self):
        line = self.marker_line()
        for indentation in (' ', '\t', '    '):
            with self.subTest(indentation=repr(indentation)):
                self.assert_cli(self.spec.replace(line, line + '\n' + indentation + line), 1,
                                'abstract post-hold declaration must occur exactly once globally')
        self.assert_cli(self.spec, 0, 'PASS: 310 declared abstract post-hold rows')

    # Count occurrences, including multiple markers on one line; do not count matching lines.
    def test_cli_multiple_markers_on_one_line(self):
        line = self.marker_line()
        self.assert_cli(self.spec.replace(line, line + ' ' + line), 1,
                        'abstract post-hold declaration must occur exactly once globally')
        self.assert_cli(self.spec, 0, 'PASS: 310 declared abstract post-hold rows')

    # A single candidate must be inside A and have the canonical line and valid JSON.
    def test_cli_single_marker_location_and_syntax(self):
        line = self.marker_line()
        without = self.spec.replace(line + '\n', '')
        for spec in (without + '\n' + line + '\n', line + '\n' + without):
            with self.subTest(location='outside A'):
                self.assert_cli(spec, 1, 'abstract post-hold declaration must be inside Appendix A')
        for replacement in (' ' + line, 'prefix ' + line, line + ' suffix',
                            line.replace('rows-v1:', 'rows-v2:'),
                            line.replace('<!-- ', '<!--\n')):
            with self.subTest(replacement=replacement[:60]):
                self.assert_cli(self.spec.replace(line, replacement), 1,
                                'malformed abstract post-hold declaration')
        self.assert_cli(self.spec.replace(line, '<!-- abstract-post-hold-rows-v1: [ -->'),
                        1, 'malformed abstract post-hold declaration JSON')
        self.assert_cli(self.spec, 0, 'PASS: 310 declared abstract post-hold rows')

    # Existing missing/in-A duplicate controls still fail through the CLI; clean stays green.
    def test_cli_missing_and_duplicate_marker_controls(self):
        line = self.marker_line()
        for spec in (self.spec.replace(line, ''), self.spec.replace(line, line + '\n' + line)):
            with self.subTest(count='zero or two'):
                self.assert_cli(spec, 1,
                                'abstract post-hold declaration must occur exactly once globally')
        self.assert_cli(self.spec, 0, 'PASS: 310 declared abstract post-hold rows')


if __name__ == '__main__':
    unittest.main()
