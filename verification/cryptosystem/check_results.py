#!/usr/bin/env python3
"""Fail closed on incomplete inventories and unexpected verifier verdicts."""
import json
import re
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_inventory(kind, directory, names):
    extension = {'proverif': 'pv', 'tamarin': 'spthy', 'verifpal': 'vp'}[kind]
    actual = {p.stem for p in Path(directory).glob(f'*.{extension}')}
    expected = set(names)
    require(len(expected) == len(names), 'duplicate model in inventory')
    require(actual == expected, f'model inventory mismatch: {actual ^ expected}')


def check_proverif(path, expected):
    output = Path(path).read_text()
    require(output.count('Verification summary:') == 1, 'missing/duplicate verification summary')
    summary = output.split('Verification summary:', 1)[1].split('---', 1)[0]
    lines = [line.strip() for line in summary.splitlines() if line.strip()]
    if expected == 'equivalent':
        require(lines == ['Observational equivalence is true.'], lines)
    elif expected == 'distinguisher':
        require(lines == ['Observational equivalence cannot be proved.'], lines)
        require('A trace has been found.' in output, 'no concrete distinguishing trace')
        require('The attacker tests whether' in output, 'missing equality test')
        require('The result in the left-hand side is different from the result in the right-hand side.' in output,
                'missing differing test outcome')
    else:
        verdicts = []
        for line in lines:
            match = re.fullmatch(r'(?:Query|Weak secret).* is (true|false)\.?', line)
            require(match, f'unrecognized verdict: {line}')
            verdicts.append(match[1])
        require(verdicts == expected.split(), f'expected {expected}; got {verdicts}')


def check_tamarin_inventory(directory):
    root = Path(directory)
    cases = [line.split() for line in (root / 'cases.tsv').read_text().splitlines()]
    require(all(len(case) == 4 and case[2] in ('c', 's', 'i') and case[3] in ('BFS', 'SEQDFS') for case in cases), 'invalid proof case')
    check_inventory('tamarin', directory, sorted({case[0] for case in cases}))
    scheduled = [(theory, lemma) for theory, lemma, _, _ in cases]
    declared = [(p.stem, lemma) for p in root.glob('*.spthy')
                for lemma in re.findall(r'^lemma\s+(\w+)', p.read_text(), re.M)]
    require(len(set(scheduled)) == len(scheduled), 'duplicate proof case')
    require(set(scheduled) == set(declared), f'proof inventory mismatch: {set(scheduled) ^ set(declared)}')


def verifpal_cases(directory):
    root = Path(directory)
    cases = json.loads((root / 'cases.json').read_text())
    check_inventory('verifpal', directory, list(cases))
    for model, modes in cases.items():
        require(set(modes) <= {'explicit', 'auto'} and 'explicit' in modes, 'invalid verification report')
        for mode, case in modes.items():
            bounds = (['1', '2', '4'] if model == 'pairing_activation' else ['1', '2', '4', '8']) if mode == 'explicit' else ['1', '2']
            require(list(case['codes']) == bounds, f'incomplete bounds for {model}/{mode}')
            require(len(set(case['queries'])) == len(case['queries']), 'duplicate query')
            for sessions in bounds:
                require(re.fullmatch(r'(?:[caef][01])+', case['codes'][sessions]), 'invalid result code')
                require(len(case['codes'][sessions]) == 2 * len(case['queries']), 'query count mismatch')
                print(model, mode, sessions)


def check_verifpal(path, manifest, model, mode, sessions):
    expected = json.loads(Path(manifest).read_text())[model][mode]
    report = json.loads(Path(path).read_text())
    require(report['version'] == '1.4.3' and report['ok'] is True, 'bad version or failed report')
    require(len(report['models']) == 1, 'wrong number of models')
    result = report['models'][0]
    require(result['ok'] is True and 'error' not in result, 'model failed')
    require(Path(result['file']).name == model + '.vp', 'wrong model file')
    analysis = result['analysis']
    require(analysis['model'] == model + '.vp' and analysis['attacker'] == 'active', 'wrong analysis')
    require(analysis['sessions'] == int(sessions), 'wrong session bound')
    require(analysis['assumptions'] == [], 'unexpected cryptographic assumption')
    queries = analysis['queries']
    require([q['query'] for q in queries] == expected['queries'], 'changed/missing/extra queries')
    code = ''
    for query in queries:
        require(type(query['resolved']) is bool, 'non-Boolean query result')
        require(query['preconditions'] == [], 'unexpected query precondition')
        require(query.get('generated', False) == (mode == 'auto'), 'wrong query origin')
        envelope = query['envelope']
        require(envelope['sessions'] == int(sessions), 'wrong query bound')
        require(envelope['exhausted'] is True and envelope['truncations'] == [], 'incomplete search')
        if query['resolved']:
            require(query['steps'], 'attack lacks reconstructed trace')
        kind = {'confidentiality': 'c', 'authentication': 'a', 'equivalence': 'e', 'freshness': 'f'}[query['kind']]
        code += kind + str(int(query['resolved']))
    require(analysis['attacks'] == sum(q['resolved'] for q in queries), 'attack count mismatch')
    require(analysis['code'] == code == expected['codes'][sessions], f'unexpected code: {code}')
    return code


if __name__ == '__main__':
    try:
        command, *args = sys.argv[1:]
        if command == 'inventory':
            check_inventory(args[0], args[1], args[2:])
        elif command == 'verifpal-cases':
            verifpal_cases(*args)
        elif command == 'verifpal':
            print(check_verifpal(*args), 'envelope=exhausted')
        elif command == 'tamarin-inventory':
            check_tamarin_inventory(*args)
        elif command == 'proverif':
            check_proverif(*args)
        else:
            raise ValueError(f'unknown command: {command}')
    except (ValueError, KeyError) as error:
        sys.exit(str(error))
