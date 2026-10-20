"""Count completed, unique paired trials using the paper's verdict categories.

Execution errors and dry runs have no verdict and are kept in a separate
execution summary. They are never converted to unsuccessful attacks. Same-day
confirmation records (phase=confirmation) are not additional measured trials.
No effectiveness-rate denominator or historical results are invented here.
"""
import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
import re

from construct_pairs import EXPECTED

VERDICTS = ('success', 'limited', 'unsuccessful')


def load_results(paths):
    for path in paths:
        with open(path, encoding='utf-8') as f:
            for number, line in enumerate(f, 1):
                if line.strip():
                    try:
                        yield json.loads(line)
                    except ValueError as exc:
                        raise ValueError('%s:%s: invalid JSON' % (path, number)) from exc


def summarize(records, *, reassess=True):
    pattern = defaultdict(Counter)
    target = defaultdict(Counter)
    target_pattern = defaultdict(Counter)
    technique = defaultdict(Counter)
    product = defaultdict(Counter)
    execution = Counter()
    seen = set()
    for r in records:
        phase = r.get('phase', 'measurement')
        if phase == 'confirmation':
            execution['confirmation_excluded'] += 1
            continue
        if phase != 'measurement':
            raise ValueError('unrecognized phase')
        pat, tid, mr = r['pattern'], r['target_id'], r['mr']
        tech = pat.split('-')[0]
        expected_mr = 'MR1' if tech in ('A1', 'A2') else ('MR2' if tech in ('A3', 'A4', 'A5') else 'MR3')
        if pat not in EXPECTED or expected_mr != mr:
            raise ValueError('pattern/MR mismatch')
        if r['pair_id'] != r['entry_id'] + '/' + tid:
            raise ValueError('pair_id does not identify entry and full target')
        if r['entry_id'].rsplit('-', 1)[0] != pat:
            raise ValueError('entry_id and pattern disagree')
        try:
            ordinal = int(r['entry_id'].rsplit('-', 1)[1])
        except (ValueError, IndexError) as exc:
            raise ValueError('invalid entry ordinal') from exc
        if not 1 <= ordinal <= EXPECTED[pat]:
            raise ValueError('entry ordinal outside frozen pattern range')
        status, verdict = r['execution_status'], r.get('verdict')
        if status not in ('completed', 'not_run', 'error'):
            raise ValueError('unknown execution status')
        if status != 'completed':
            if verdict is not None:
                raise ValueError('unexecuted/failed trials cannot carry a verdict')
            execution[status] += 1
            continue
        if verdict not in VERDICTS or (verdict == 'limited' and mr != 'MR3'):
            raise ValueError('verdict does not match the paper categories')
        if r.get('error'):
            raise ValueError('completed record contains an execution error')
        if reassess:
            from execution import assess
            if not isinstance(r.get('observations'), dict):
                raise ValueError('completed record lacks observations for reassessment')
            computed = assess({'mr': mr}, r['observations'])
            if computed['verdict'] != verdict:
                raise ValueError('stored verdict disagrees with current MR assessment: %s' % r['pair_id'])
        key = (r['entry_id'], tid)
        if key in seen:
            raise ValueError('duplicate measured trial %s; mark repeat checks as confirmation' % (key,))
        seen.add(key)
        execution['completed'] += 1
        for bucket in [pattern[(pat, mr)], target[tid], target_pattern[(tid, pat, mr)],
                       technique[(tech, mr)], product[(tid, tech)]]:
            bucket[verdict] += 1
    return {'by_pattern': pattern, 'by_target': target,
            'by_target_pattern': target_pattern, 'by_technique': technique,
            'product': product, 'execution': execution}


def write_csvs(summary, out_prefix):
    out = Path(out_prefix)
    out.parent.mkdir(parents=True, exist_ok=True)
    layouts = [('by_pattern', ['pattern', 'mr']), ('by_target', ['target_id']),
               ('by_target_pattern', ['target_id', 'pattern', 'mr']),
               ('by_technique', ['technique', 'mr'])]
    for name, columns in layouts:
        with open(str(out) + '_' + name + '.csv', 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(columns + ['completed_trials', *VERDICTS])
            for key, counts in sorted(summary[name].items()):
                key = key if isinstance(key, tuple) else (key,)
                w.writerow([*key, sum(counts[v] for v in VERDICTS),
                            *(counts[v] for v in VERDICTS)])
    with open(str(out) + '_product_outcomes.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['target_id', 'technique', 'outcome'])
        for key, counts in sorted(summary['product'].items()):
            outcome = 'success' if counts['success'] else ('limited' if counts['limited'] else 'unsuccessful')
            w.writerow([*key, outcome])
    Path(str(out) + '_execution_summary.json').write_text(
        json.dumps(dict(summary['execution']), indent=2) + '\n', encoding='utf-8')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('results', nargs='+')
    ap.add_argument('--out-prefix', default='summary')
    ap.add_argument('--counts-only', action='store_true',
                    help='count existing labels only; does not validate measurement verdicts')
    args = ap.parse_args()
    summary = summarize(load_results(args.results), reassess=not args.counts_only)
    write_csvs(summary, args.out_prefix)
    print('Validation mode:', 'COUNTS ONLY (no observation validation)' if args.counts_only else 'REASSESSED from observations')
    print('Completed trial counts:', summary['execution'].get('completed', 0),
          '(dry runs, errors and confirmation checks are separate)')


if __name__ == '__main__':
    main()
