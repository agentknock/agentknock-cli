"""Regression tests for false-green failure modes in verifier output handling."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

import check_results as checks


class ResultChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.report = self.root / 'report'

    def test_proverif_does_not_drop_unknown_or_extra_queries(self):
        good = 'Verification summary:\nQuery not attacker(secret) is true.\n---\n'
        self.report.write_text(good)
        checks.check_proverif(self.report, 'true')
        for line in ['Query not attacker(other) cannot be proved.',
                     'Query not attacker(other) is true.']:
            self.report.write_text(good.replace('---', line + '\n---'))
            with self.subTest(line=line), self.assertRaises(ValueError):
                checks.check_proverif(self.report, 'true')

    def test_unknown_equivalence_needs_a_concrete_distinguisher(self):
        unknown = 'Verification summary:\nObservational equivalence cannot be proved.\n---'
        self.report.write_text(unknown)
        for expected in ['equivalent', 'distinguisher']:
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                checks.check_proverif(self.report, expected)
        self.report.write_text('The attacker tests whether two terms are equal.\n'
                               'The result in the left-hand side is different from the result in the right-hand side.\n'
                               'A trace has been found.\n' + unknown)
        checks.check_proverif(self.report, 'distinguisher')

    def test_inventory_cannot_silently_skip_a_model_or_lemma(self):
        (self.root / 'a.pv').touch()
        (self.root / 'b.pv').touch()
        with self.assertRaises(ValueError):
            checks.check_inventory('proverif', self.root, ['a'])
        (self.root / 'a.spthy').write_text('lemma one:\nlemma two:\n')
        (self.root / 'cases.tsv').write_text('a one c SEQDFS\n')
        with self.assertRaises(ValueError):
            checks.check_tamarin_inventory(self.root)
        (self.root / 'cases.tsv').write_text('a one c SEQDFS\na two s BFS\n')
        checks.check_tamarin_inventory(self.root)
        (self.root / 'cases.tsv').write_text('a one cs SEQDFS\na two s BFS\n')
        with self.assertRaises(ValueError):
            checks.check_tamarin_inventory(self.root)

    def test_verifpal_checks_each_query_and_its_search_envelope(self):
        manifest = self.root / 'cases.json'
        manifest.write_text(json.dumps({'model': {'explicit': {
            'queries': ['confidentiality? secret'], 'codes': {'2': 'c0'}}}}))
        good = {'version': '1.4.3', 'ok': True, 'models': [{
            'file': 'model.vp', 'ok': True, 'analysis': {
                'model': 'model.vp', 'attacker': 'active', 'sessions': 2,
                'assumptions': [], 'code': 'c0', 'attacks': 0, 'queries': [{
                    'query': 'confidentiality? secret', 'kind': 'confidentiality',
                    'resolved': False, 'preconditions': [], 'steps': [],
                    'envelope': {'sessions': 2, 'exhausted': True, 'truncations': []}
                }]}}]}
        self.report.write_text(json.dumps(good))
        checks.check_verifpal(self.report, manifest, 'model', 'explicit', '2')
        mutations = [
            lambda a: a.update(sessions=1),
            lambda a: a.update(queries=[]),
            lambda a: a['queries'].append(copy.deepcopy(a['queries'][0])),
            lambda a: a['queries'][0].update(query='confidentiality? other'),
            lambda a: a['queries'][0].update(preconditions=['after deletion']),
            lambda a: a['queries'][0]['envelope'].update(exhausted=False),
            lambda a: a['queries'][0]['envelope'].update(truncations=['limit']),
            lambda a: a['queries'][0]['envelope'].update(sessions=1),
            lambda a: a['queries'][0].update(resolved=True),
        ]
        for index, mutate in enumerate(mutations):
            broken = copy.deepcopy(good)
            mutate(broken['models'][0]['analysis'])
            self.report.write_text(json.dumps(broken))
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                checks.check_verifpal(self.report, manifest, 'model', 'explicit', '2')


if __name__ == '__main__':
    unittest.main()
