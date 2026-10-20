# -*- coding: utf-8 -*-
"""ConstructPairs: the 26-pattern fixed construction catalog (77,208 entries).

Implements the construction patterns defined in the paper (Section
"Input Construction and Mutation Strategies", Table `mutation_budget`, and
Appendix "Mutation Parameter Details"). Enumeration is deterministic; running

    python construct_pairs.py --selfcheck

verifies every pattern count against the published table and the 77,208 total.
`--emit` writes the full catalog (JSONL, gzipped) and a per-pattern count CSV.

Each catalog entry is one construction: a (reference L1, attack input L2) pair.
Entries are target-independent; the trial count is entries x targets
(A1-A2: 27 SEG-client combinations; A3-A7: 14 Web clients).

Honesty note: this module implements the INPUT catalog only. It generates no
measurement results. Per-entry delivery, observation, and MR assessment are
performed by the runner modules (see run_seg_path.py / run_client_path.py).
"""
import argparse
import csv
import gzip
import itertools
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dictionaries as D  # noqa: E402

# Published per-pattern counts (paper Table "Parameterized construction entries").
EXPECTED = {
    'A1-1': 3, 'A1-2': 7, 'A1-3': 1, 'A1-4': 1249, 'A1-5': 48,
    'A2': 63488,
    'A3-1': 64, 'A3-2': 30, 'A3-3': 9, 'A3-4': 11,
    'A4-1': 6, 'A4-2': 127, 'A4-3': 12, 'A4-4': 8, 'A4-5': 10848, 'A4-6': 3,
    'A5-1': 3, 'A5-2': 2, 'A5-3': 3, 'A5-4': 2,
    'A6-1': 22, 'A6-2': 234, 'A6-3': 22, 'A6-4': 650,
    'A7-1': 292, 'A7-2': 64,
}
TOTAL_EXPECTED = 77208
PATTERN_ORDER = list(EXPECTED.keys())
TECHNIQUE = {p: p.split('-')[0] for p in PATTERN_ORDER}
# MR and target multiplier per technique.
MR_OF = {'A1': 'MR1', 'A2': 'MR1', 'A3': 'MR2', 'A4': 'MR2', 'A5': 'MR2',
         'A6': 'MR3', 'A7': 'MR3'}
TARGETS_OF = {'A1': 27, 'A2': 27, 'A3': 14, 'A4': 14, 'A5': 14, 'A6': 14, 'A7': 14}

C = []  # catalog entries
ENTRY_COUNTERS = {}
A6_LABEL_COUNTS = {}


def _u(cp):
    return 'U+%04X' % cp


def add(pattern, params, l1, l2, carrier, representation='raw', **extra):
    ENTRY_COUNTERS[pattern] = ENTRY_COUNTERS.get(pattern, 0) + 1
    C.append(dict(entry_id='%s-%04d' % (pattern, ENTRY_COUNTERS[pattern]),
                  pattern=pattern, technique=TECHNIQUE[pattern], mr=MR_OF[TECHNIQUE[pattern]],
                  targets=TARGETS_OF[TECHNIQUE[pattern]],
                  params=params, reference=l1, attack_input=l2, carrier=carrier,
                  representation=representation, **extra))


def anchor(url):
    """Reference/attack link carrier for anchor-based constructions."""
    return url


# --------------------------------------------------------------------------
# A1
# --------------------------------------------------------------------------
def gen_a1_1():
    """A1-1 Comment or hidden span: comment-only, hidden-span-only, combined."""
    comment = '<!-- %s -->' % D.ATTACKER_ROOT
    hidden = '<span style="display:none">%s</span>' % D.ATTACKER_ROOT
    for name, carrier_desc in (('comment only', comment), ('hidden span only', hidden),
                               ('combined containers', comment + hidden)):
        add('A1-1', name, D.ATTACKER_ROOT, D.ATTACKER_ROOT, 'container',
            container_html=carrier_desc)


def gen_a1_2():
    """A1-2 Fullwidth slash: all nonempty replacement subsets of the 3 slashes."""
    slash_idx = [i for i, ch in enumerate(D.A1_BASE_URL) if ch == '/']
    assert len(slash_idx) == 3
    for mask in range(1, 8):
        sel = [i for i in range(3) if mask >> i & 1]
        chars = list(D.A1_BASE_URL)
        for i in sel:
            chars[slash_idx[i]] = '\uFF0F'
        add('A1-2', 'replace slashes at positions %s with U+FF0F' % sel,
            D.ATTACKER_ROOT, ''.join(chars), 'plain_text')


def gen_a1_3():
    """A1-3 Plain-text URL: one scheme-less domain in a <p> without an anchor."""
    add('A1-3', 'scheme-less domain, plain text in <p>', D.ATTACKER_ROOT,
        'www.malicious.com', 'plain_text')


def _a1_insert(cp, run_len, pos):
    run = chr(cp) * run_len
    return {
        'colon_after': 'https:%s//www.malicious.com/page' % run,
        'host_start': 'https://%swww.malicious.com/page' % run,
        'label_boundary': 'https://www.malicious%s.com/page' % run,
        'path_start': 'https://www.malicious.com/%spage' % run,
        'query_start': 'https://www.malicious.com/page?%s' % run,
        'url_end': 'https://www.malicious.com/page%s' % run,
    }[pos]


def gen_a1_4():
    """A1-4 Whitespace: 25 x 6 positions x runs 1-8, minus the single U+00A0
    after the HTTPS scheme colon; plus interleaving over the host label or the
    whole URL (25 x 2)."""
    positions = ['colon_after', 'host_start', 'label_boundary', 'path_start',
                 'query_start', 'url_end']
    for cp in D.WHITE_SPACE:
        for pos in positions:
            for k in range(1, 9):
                if cp == 0x00A0 and pos == 'colon_after' and k == 1:
                    continue  # excluded from the fixed input set (paper A1-4)
                add('A1-4', '%s at %s, run_length=%d' % (_u(cp), pos, k),
                    D.ATTACKER_ROOT, _a1_insert(cp, k, pos), 'plain_text')
    # interleave: host label and whole URL
    for cp in D.WHITE_SPACE:
        ch = chr(cp)
        host_label_interleaved = 'https://www.%s.com/page' % ch.join(D.A1_HOST_LABEL)
        whole_url_interleaved = ch.join(D.A1_BASE_URL)
        add('A1-4', '%s interleaved over host label' % _u(cp),
            D.ATTACKER_ROOT, host_label_interleaved, 'plain_text')
        add('A1-4', '%s interleaved over whole URL' % _u(cp),
            D.ATTACKER_ROOT, whole_url_interleaved, 'plain_text')


def gen_a1_5():
    """A1-5 Zero-width space: U+200B at 6 positions, run lengths 1-8."""
    positions = ['colon_after', 'host_start', 'label_boundary', 'path_start',
                 'query_start', 'url_end']
    for pos in positions:
        for k in range(1, 9):
            add('A1-5', 'U+200B at %s, run_length=%d' % (pos, k),
                D.ATTACKER_ROOT, _a1_insert(0x200B, k, pos), 'plain_text')


# --------------------------------------------------------------------------
# A2
# --------------------------------------------------------------------------
def gen_a2():
    """A2 Unicode delimiter truncation: scheme-less plain text
    www.malicious.com[c]whitelisted.com, [c] over U+0000-U+FFFF except
    U+D800-U+DFFF (63,488; U+002E dot control included)."""
    for cp in range(0x10000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        add('A2', 'delimiter %s' % _u(cp), D.ATTACKER_ROOT,
            'www.malicious.com%swhitelisted.com' % chr(cp), 'plain_text')


# --------------------------------------------------------------------------
# A3
# --------------------------------------------------------------------------
def gen_a3_1():
    """A3-1 Dash or underscore: 8 boundaries of the 7-char label `trusted`
    (ends included) x {dash, underscore} x repeat 1-4."""
    label = 'trusted'
    for b in range(len(label) + 1):
        for ch in ('-', '_'):
            for k in range(1, 5):
                mut = label[:b] + ch * k + label[b:]
                add('A3-1', "boundary=%d, char='%s', repeat=%d" % (b, ch, k),
                    D.ATTACKER_ROOT, anchor('https://%s.com/' % mut), 'html_anchor')


def gen_a3_2():
    """A3-2 Keyword repetition: within-label and dot-separated, 2-16 times."""
    label = 'trusted'
    for k in range(2, 17):
        add('A3-2', 'within-label repetition x%d' % k,
            D.ATTACKER_ROOT, anchor('https://%s.com/' % (label * k)), 'html_anchor')
    for k in range(2, 17):
        add('A3-2', 'dot-separated repetition x%d' % k,
            D.ATTACKER_ROOT, anchor('https://%s.com/' % '.'.join([label] * k)), 'html_anchor')


def gen_a3_3():
    """A3-3 Subdomain prefix: depth 0-8 from the fixed ordered prefix list;
    the controlled suffix .malicious.com is unchanged."""
    for depth in range(0, 9):
        labels = D.A3_PREFIX_LABELS[:depth] + ['whitelisted.com']
        host = '.'.join(labels) + '.malicious.com'
        add('A3-3', 'prefix depth %d (labels: %s)' % (depth, labels[:-1] or ['(none)']),
            D.ATTACKER_ROOT, anchor('https://%s/' % host), 'html_anchor')


def gen_a3_4():
    """A3-4 Suffix variation: 11 selected suffixes on the trusted name."""
    for sfx in D.A3_SUFFIXES:
        add('A3-4', 'suffix %s' % sfx,
            D.ATTACKER_ROOT, anchor('https://www.whitelisted%s/' % sfx), 'html_anchor')


# --------------------------------------------------------------------------
# A4
# --------------------------------------------------------------------------
def _pct_encode_depth(first_level, depth):
    """depth 1 = %xx; depth d wraps the previous form's % (e.g. %40 -> %2540)."""
    s = first_level
    for _ in range(depth - 1):
        s = '%25' + s[1:]
    return s


def gen_a4_1():
    """A4-1 Repeated encoding: separators @ (userinfo) and / (path separator
    between two fixed segments) at encoding depths 2-4."""
    at_first = '%40'   # depth-1 encoding of @
    sl_first = '%2F'   # depth-1 encoding of /
    for depth in (2, 3, 4):
        sep = _pct_encode_depth(at_first, depth)
        add('A4-1', 'userinfo @ at encoding depth %d (%s)' % (depth, sep),
            D.ATTACKER_ROOT, anchor('https://whitelisted.com%smalicious.com/' % sep),
            'html_anchor')
    for depth in (2, 3, 4):
        sep = _pct_encode_depth(sl_first, depth)
        add('A4-1', 'path separator at encoding depth %d (%s)' % (depth, sep),
            D.ATTACKER_ROOT, anchor('https://malicious.com/a%sb/' % sep), 'html_anchor')


def gen_a4_2():
    """A4-2 Mixed raw/encoded spelling: all nonempty encoding subsets of the
    7 positions in `trusted`; remaining domain suffix .malicious.com unchanged."""
    enc = {'t': '%74', 'r': '%72', 'u': '%75', 's': '%73', 'e': '%65', 'd': '%64'}
    label = 'trusted'
    for mask in range(1, 128):
        chars = []
        for i, ch in enumerate(label):
            chars.append(enc[ch] if mask >> i & 1 else ch)
        add('A4-2', 'encoded positions %s' % [i for i in range(7) if mask >> i & 1],
            D.ATTACKER_ROOT, anchor('https://%s.malicious.com/' % ''.join(chars)),
            'html_anchor')


def gen_a4_3():
    """A4-3 Query/fragment placement: query-only, fragment-only, or both, at
    one of 4 positions j; `both` uses the same j in both components."""
    def query_url(j):
        fields = ['%s=%s' % (f, D.A4_QUERY_FILLER) for f in D.A4_QUERY_FIELDS]
        fields[j - 1] = '%s=whitelisted.com' % D.A4_QUERY_FIELDS[j - 1]
        return 'https://malicious.com/?%s' % '&'.join(fields)

    def fragment_url(j):
        segs = list(D.A4_FRAGMENT_SEGMENTS)
        segs[j - 1] = 'whitelisted.com'
        return 'https://malicious.com/#%s' % '/'.join(segs)

    for j in range(1, 5):
        add('A4-3', 'query-only, j=%d' % j, D.ATTACKER_ROOT, anchor(query_url(j)), 'html_anchor')
        add('A4-3', 'fragment-only, j=%d' % j, D.ATTACKER_ROOT, anchor(fragment_url(j)), 'html_anchor')
        add('A4-3', 'both (same j=%d)' % j, D.ATTACKER_ROOT,
            anchor(query_url(j) + fragment_url(j)[fragment_url(j).index('#'):]), 'html_anchor')


def gen_a4_4():
    """A4-4 Trusted name in the path: 8 predetermined path-segment positions."""
    for i in range(8):
        segs = list(D.A4_PATH_SEGMENTS)
        segs[i] = 'whitelisted.com'
        add('A4-4', 'trusted name at path segment %d' % (i + 1),
            D.ATTACKER_ROOT, anchor('https://malicious.com/%s/' % '/'.join(segs)),
            'html_anchor')


def gen_a4_5():
    """A4-5 Unicode insertion in non-host components: 3 fixed-position templates;
    ordered sequences of length 1-3 over the 15-char format dictionary
    (with repetition), plus U+2100 alone at each position."""
    templates = [
        ('path', 'https://malicious.com/{s}whitelisted.com',
         'https://malicious.com/whitelisted.com'),
        ('query', 'https://malicious.com/?name={s}whitelisted.com',
         'https://malicious.com/?name=whitelisted.com'),
        ('fragment', 'https://malicious.com/#{s}whitelisted.com',
         'https://malicious.com/#whitelisted.com'),
    ]
    seqs = []
    for n in (1, 2, 3):
        seqs.extend(itertools.product(D.FORMAT_CHARS, repeat=n))
    assert len(seqs) == 15 + 225 + 3375 == 3615
    for pos_name, tmpl, ref in templates:
        for seq in seqs:
            s = ''.join(chr(cp) for cp in seq)
            add('A4-5', '%s position, inserted [%s] (len %d)'
                % (pos_name, ','.join(_u(c) for c in seq), len(seq)),
                anchor(ref), tmpl.format(s=s), 'html_anchor')
        for cp in D.A4_5_EXTRA_CHARS:
            add('A4-5', '%s position, inserted [%s] alone' % (pos_name, _u(cp)),
                anchor(ref), tmpl.format(s=chr(cp)), 'html_anchor')


def gen_a4_6():
    """A4-6 Userinfo and separator representation: literal @, %40, %2540."""
    forms = [('literal @', '@'), ('%40', '%40'), ('%2540', '%2540')]
    for name, sep in forms:
        add('A4-6', 'userinfo separator: %s' % name,
            D.ATTACKER_ROOT, anchor('https://whitelisted.com%smalicious.com/' % sep),
            'html_anchor')


# --------------------------------------------------------------------------
# A5
# --------------------------------------------------------------------------
def gen_a5():
    """A5 patterns: redirect entries and destination-parameter forms.

    All entry hosts are ROLE placeholders mapped through
    the external private domain configuration to actually registered, controlled redirect
    services. Each entry must be verified (trust property + redirect behavior)
    before delivery, per the paper's execution conditions. Replacing a failed
    entry is an equivalent substitution and does not add constructions.
    """
    m = D.A5_ATTCKER_DEST
    entries = [
        ('A5-1', 'chain: trusted subdomain entry -> external hop -> attacker',
         'https://sub.whitelisted.com/redirect?to=https://hop1.example.net/forward?target=%s' % m),
        ('A5-1', 'chain: trusted entry -> hop1 -> hop2 -> attacker (3 hops)',
         'https://sub.whitelisted.com/redirect?to=https://hop1.example.net/forward?target='
         'https://hop2.example.net/forward?target=%s' % m),
        ('A5-1', 'chain: trusted main-domain entry -> trusted subdomain entry -> attacker',
         'https://whitelisted.com/exit?url=https://sub.whitelisted.com/redirect?to=%s' % m),
        ('A5-2', 'open redirect on trusted main domain (url parameter)',
         'https://whitelisted.com/exit?url=%s' % m),
        ('A5-2', 'open redirect on trusted subdomain (goto parameter)',
         'https://sub.whitelisted.com/?goto=%s' % m),
        ('A5-3', 'destination parameter target=',
         'https://sub.whitelisted.com/redirect?target=%s' % m),
        ('A5-3', 'destination parameter continue=',
         'https://sub.whitelisted.com/redirect?continue=%s' % m),
        ('A5-3', 'destination parameter next=',
         'https://sub.whitelisted.com/redirect?next=%s' % m),
        ('A5-4', 'search-service redirector, entry form /url?q=',
         'https://search.example.net/url?q=%s' % m),
        ('A5-4', 'search-service redirector, entry form /link?u=',
         'https://search.example.net/link?u=%s' % m),
    ]
    for pattern, params, url in entries:
        add(pattern, params, D.ATTACKER_ROOT, anchor(url), 'html_anchor')


# --------------------------------------------------------------------------
# A6
# --------------------------------------------------------------------------
def _puny(host):
    return host.encode('idna').decode('ascii')


def gen_a6():
    """A6 homograph substitutions over tealeaves / monsoon / puppeteer.

    Enumerates every assignment of counterparts (or unchanged) to the mutable
    positions, excluding the all-Latin label. Each resulting label is emitted
    twice: Unicode representation and Punycode representation (928 entries =
    464 labels x 2). Classification into A6-1..A6-4 follows the substitution
    structure; the per-pattern counts are asserted in --selfcheck.
    """
    global A6_LABEL_COUNTS
    def classify(cyr_positions, grk_positions, n_positions):
        changed = sorted(cyr_positions | grk_positions)
        if not changed:
            return None
        if cyr_positions and grk_positions:
            return 'A6-4'
        if len(changed) == 1:
            return 'A6-1' if cyr_positions else 'A6-3'
        return 'A6-2'

    label_counts = {'A6-1': 0, 'A6-2': 0, 'A6-3': 0, 'A6-4': 0}
    for name, pos_map in D.A6_NAMES.items():
        positions = sorted(pos_map)
        choice_lists = [[None] + pos_map[p] for p in positions]
        for combo in itertools.product(*choice_lists):
            if all(c is None for c in combo):
                continue
            chars = list(name)
            cyr_pos, grk_pos = set(), set()
            for p, choice in zip(positions, combo):
                if choice == 'cyrillic':
                    chars[p] = D.CYRILLIC_MAP[name[p]]
                    cyr_pos.add(p)
                elif choice == 'greek':
                    chars[p] = D.GREEK_MAP[name[p]]
                    grk_pos.add(p)
            label = ''.join(chars)
            pat = classify(cyr_pos, grk_pos, positions)
            label_counts[pat] += 1
            ref = anchor('https://%s.com/' % name)
            uni_host = '%s.com' % label
            puny_label = label.encode('idna').decode('ascii')
            puny_host = '%s.com' % puny_label
            add(pat, 'base=%s, substitutions at %s, Unicode representation'
                % (name, sorted(p for p, c in zip(positions, combo) if c)),
                ref, anchor('https://%s/' % uni_host), 'html_anchor',
                representation='unicode', punycode_form='https://%s/' % puny_host)
            add(pat, 'base=%s, substitutions at %s, Punycode representation'
                % (name, sorted(p for p, c in zip(positions, combo) if c)),
                ref, anchor('https://%s/' % puny_host), 'html_anchor',
                representation='punycode', unicode_form='https://%s/' % uni_host)
    A6_LABEL_COUNTS.clear()
    A6_LABEL_COUNTS.update(label_counts)
    return label_counts


# --------------------------------------------------------------------------
# A7
# --------------------------------------------------------------------------
def gen_a7():
    """A7 direction-control constructions over 4 names x {http, https}.

    A7-1: enclose one nonempty contiguous name segment between U+202E and
    U+202C, preserving the segment's logical character order.
    A7-2: insert U+202E before a selected name suffix and reverse that suffix,
    without U+202C.
    """
    RLO, PDF = '\u202e', '\u202c'
    for name in D.A7_NAMES:
        n = len(name)
        for scheme in D.A7_SCHEMES:
            ref = anchor('%s://www.%s.com/' % (scheme, name))
            for i in range(n):
                for j in range(i, n):
                    label = name[:i] + RLO + name[i:j + 1] + PDF + name[j + 1:]
                    add('A7-1', 'name=%s, segment [%d,%d], scheme %s (terminated run)'
                        % (name, i, j, scheme),
                        ref, anchor('%s://www.%s.com/' % (scheme, label)), 'html_anchor')
            for i in range(n):
                label = name[:i] + RLO + name[i:][::-1]
                add('A7-2', 'name=%s, suffix start %d, scheme %s (unterminated run)'
                    % (name, i, scheme),
                    ref, anchor('%s://www.%s.com/' % (scheme, label)), 'html_anchor')


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------
def build_catalog():
    C.clear()
    ENTRY_COUNTERS.clear()
    A6_LABEL_COUNTS.clear()
    for f in (gen_a1_1, gen_a1_2, gen_a1_3, gen_a1_4, gen_a1_5, gen_a2,
              gen_a3_1, gen_a3_2, gen_a3_3, gen_a3_4,
              gen_a4_1, gen_a4_2, gen_a4_3, gen_a4_4, gen_a4_5, gen_a4_6,
              gen_a5, gen_a6, gen_a7):
        f()
    # re-assign sequential entry ids per pattern (generators above may emit
    # interleaved A6 patterns; ids are finalized here in emission order)
    counters = {}
    for e in C:
        counters[e['pattern']] = counters.get(e['pattern'], 0) + 1
        e['entry_id'] = '%s-%04d' % (e['pattern'], counters[e['pattern']])
    return list(C)


def selfcheck():
    build_catalog()
    counts = {}
    for e in C:
        counts[e['pattern']] = counts.get(e['pattern'], 0) + 1
    ok = True
    print('%-6s %8s %8s' % ('pattern', 'expected', 'generated'))
    for p in PATTERN_ORDER:
        got = counts.get(p, 0)
        mark = 'OK' if got == EXPECTED[p] else 'MISMATCH'
        if got != EXPECTED[p]:
            ok = False
        print('%-6s %8d %8d  %s' % (p, EXPECTED[p], got, mark))
    total = len(C)
    print('%-6s %8d %8d  %s' % ('total', TOTAL_EXPECTED, total,
                                'OK' if total == TOTAL_EXPECTED else 'MISMATCH'))
    if total != TOTAL_EXPECTED:
        ok = False
    # sanity: A6 punycode of the canonical example matches the paper
    assert 'te\u0430leaves'.encode('idna').decode('ascii') == 'xn--teleaves-26g'
    print('A6 canonical Punycode check: xn--teleaves-26g  OK')
    exp_labels = {'A6-1': 11, 'A6-2': 117, 'A6-3': 11, 'A6-4': 325}
    assert A6_LABEL_COUNTS == exp_labels, (A6_LABEL_COUNTS, exp_labels)
    print('A6 label classification (464 labels): %s  OK' % A6_LABEL_COUNTS)
    print('RESULT:', 'PASS' if ok else 'FAIL')
    return ok


def emit(out_dir):
    build_catalog()
    os.makedirs(out_dir, exist_ok=True)
    gz_path = os.path.join(out_dir, 'catalog.jsonl.gz')
    # Stable gzip header and UTF-8/LF serialization, including on Windows.
    with open(gz_path, 'wb') as raw:
        with gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as f:
            for e in C:
                f.write((json.dumps(e, ensure_ascii=False) + '\n').encode('utf-8'))
    csv_path = os.path.join(out_dir, 'catalog_counts.csv')
    counts = {}
    for e in C:
        counts[e['pattern']] = counts.get(e['pattern'], 0) + 1
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['pattern', 'technique', 'mr', 'targets_per_entry', 'constructions',
                    'trials_if_full_run'])
        for p in PATTERN_ORDER:
            t = TECHNIQUE[p]
            w.writerow([p, t, MR_OF[t], TARGETS_OF[t], counts[p], counts[p] * TARGETS_OF[t]])
        w.writerow(['total', '', '', '', len(C),
                    sum(counts[p] * TARGETS_OF[TECHNIQUE[p]] for p in PATTERN_ORDER)])
    print('wrote %s (%d entries)' % (gz_path, len(C)))
    print('wrote %s' % csv_path)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--selfcheck', action='store_true',
                    help='verify per-pattern counts against the published table')
    ap.add_argument('--emit', metavar='OUT_DIR',
                    help='write the full catalog (catalog.jsonl.gz) and count CSV')
    args = ap.parse_args()
    if not (args.selfcheck or args.emit):
        ap.error('use --selfcheck and/or --emit OUT_DIR')
    if args.selfcheck and not selfcheck():
        sys.exit(1)
    if args.emit:
        emit(args.emit)


if __name__ == '__main__':
    main()
