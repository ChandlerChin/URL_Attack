# Construction parameter list (26 patterns, 77,208 constructions)

This list restates, for release review, the construction rules exactly as
published in the paper (Section *Input Construction and Mutation Strategies*,
Table `mutation_budget`, and Appendix *Mutation Parameter Details*). It uses
the paper's **current** A2 and A4-5 definitions. It contains **no** per-vendor
results. Every count below is verified by running:

    python code/construct_pairs.py --selfcheck

which regenerates the catalog deterministically and asserts each count.

General conventions: L1 = ordinary reference link (for most patterns the
attacker domain itself); L2 = constructed attack input. Constructions are
target-independent; trials = constructions x targets (A1-A2: 27 SEG-client
combinations; A3-A7: 14 Web clients). Role domains (`www.malicious.com`,
`www.whitelisted.com`) are placeholders mapped to registered test domains at
delivery time (the external private domain configuration).

## A1 - URL parsing-layer confusion (1,308 constructions; MR1; 27 targets)

| Pattern | Rule | Dictionary / range | Count |
|---|---|---|---:|
| A1-1 | HTML comment / hidden span containers around the URL | {comment only, hidden span only, combined} | 3 |
| A1-2 | Replace nonempty subsets of the 3 `/` separators with U+FF0F | subsets of 3 positions = 2^3 - 1 | 7 |
| A1-3 | Scheme-less domain `www.malicious.com` as plain text in `<p>` | fixed | 1 |
| A1-4 | Whitespace insertion: 6 positions x run lengths 1-8; plus interleaving over host label and whole URL | 25-char Unicode White_Space=yes set (U+0009-000D, 0020, 0085, 00A0, 1680, 2000-200A, 2028, 2029, 202F, 205F, 3000) | 25x6x8 - 1 + 25x2 = **1,249** |
| A1-5 | U+200B insertion: 6 positions x run lengths 1-8 | single code point | 48 |
| **A1 total** | | | **1,308** |

A1-4 exclusion: (U+00A0, scheme-colon position, run length 1) is excluded from
the fixed input set (paper A1-4), giving 1,199 single-position entries; the 50
interleave entries (25 chars x {host label, whole URL}) complete the pattern.

## A2 - Unicode delimiter truncation (63,488; MR1; 27 targets)

| Pattern | Rule | Dictionary / range | Count |
|---|---|---|---:|
| A2 | Scheme-less plain text `www.malicious.com` + [c] + `whitelisted.com`, [c] over the whole BMP except surrogates | [c] in U+0000-U+FFFF \ {U+D800-U+DFFF}; U+002E (dot) is the unperturbed control | 65,536 - 2,048 = **63,488** |

## A3 - Domain-structure confusion (114; MR2; 14 targets)

| Pattern | Rule | Dictionary / range | Count |
|---|---|---|---:|
| A3-1 | Dash/underscore inserted at one of the 8 boundaries of the 7-char label `trusted` (ends included), repeats 1-4 | {-, _} x {1..4} | 8x2x4 = 64 |
| A3-2 | Keyword repetition: within-label and dot-separated | repetition 2-16 | 15 + 15 = 30 |
| A3-3 | Subdomain prefix: depth 0-8 from a fixed ordered prefix list (`login`, `secure`, `account`, `mail`, `auth`, `my`, `www`, `signin`); controlled suffix `.malicious.com` unchanged | depths 0-8 | 9 |
| A3-4 | Suffix variation on the trusted name | 11 selected suffixes (.co, .br, .co.uk, .com.br, .org, .net, .io, .dev, .co.jp, .com.cn, .app) | 11 |
| **A3 total** | | | **114** |

## A4 - Trusted-token position/encoding confusion (11,004; MR2; 14 targets)

| Pattern | Rule | Dictionary / range | Count |
|---|---|---|---:|
| A4-1 | Repeated encoding of separators: `@` (userinfo) and `/` (path), encoding depths 2-4 | 2 separators x 3 depths | 6 |
| A4-2 | Mixed raw/percent-encoded spelling of `trusted`: every nonempty encoding subset of its 7 positions; suffix `.malicious.com` unchanged | subsets of 7 positions = 2^7 - 1 | 127 |
| A4-3 | Trusted name in query and/or fragment at one of 4 positions j (fields p1-p4 / segments s1-s4); `both` uses the same j | {query-only, fragment-only, both} x j=1..4 | 12 |
| A4-4 | Trusted name replacing one of 8 fixed path segments (docs, img, assets, static, login, api, help, view) | 8 positions | 8 |
| A4-5 | Unicode insertion in non-host components: 3 fixed-position templates (path / query / fragment); ordered format-character sequences of length 1-3 (with repetition), plus U+2100 alone per position | 15-char format-character set (U+00AD, 061C, 180E, 200B-200D, 2060-2064, FEFF, FFF9-FFFB); 15+15^2+15^3 = 3,615 per position, +1 | 3 x (3,615 + 1) = **10,848** |
| A4-6 | Userinfo separator representation: literal `@`, `%40`, `%2540` | 3 forms | 3 |
| **A4 total** | | | **11,004** |

## A5 - Redirect-chain structure (10; MR2; 14 targets)

| Pattern | Rule | Range | Count |
|---|---|---|---:|
| A5-1 | Multi-hop chains through trusted entry(ies) | 3 chains | 3 |
| A5-2 | Open redirect on trusted main/sub domain (url= / goto=) | 2 | 2 |
| A5-3 | Destination-parameter forms (target= / continue= / next=) | 3 | 3 |
| A5-4 | Search-service redirector entries (/url?q=, /link?u=) | 2 | 2 |
| **A5 total** | | | **10** |

A5 entries are **test conditions, not mutation dimensions**: each entry must be
verified for the trust property and redirect behavior before delivery;
a qualified replacement is recorded before execution. It is not a new mutation
dimension, and it must not be silently substituted after observing an outcome.

## A6 - Homograph substitution (928; MR3; 14 targets)

| Pattern | Rule | Dictionary / range | Count |
|---|---|---|---:|
| A6-1 | Single Cyrillic substitution | 11 labels, each Unicode and Punycode | 22 |
| A6-2 | Two or more substitutions from one non-Latin script (Cyrillic or Greek) | 117 labels, each Unicode and Punycode | 234 |
| A6-3 | Single Greek substitution | 11 labels, each Unicode and Punycode | 22 |
| A6-4 | Both Cyrillic and Greek substitutions in one label | 325 labels, each Unicode and Punycode | 650 |
| **A6 total** | All nonempty assignments over the fixed mutable positions | 464 distinct labels, each in two representations | **928** |

Cyrillic counterparts: a -> U+0430, e -> U+0435, o -> U+043E.
Greek counterparts: a -> U+03B1, e -> U+03B5, p -> U+03C1.
The representation count is used uniformly in every A6 pattern row.

Canonical check: `te\u0430leaves` -> `xn--teleaves-26g` (asserted in the
selfcheck).

## A7 - Bidirectional control characters (356; MR3; 14 targets)

| Pattern | Rule | Dictionary / range | Count |
|---|---|---|---:|
| A7-1 | Enclose one nonempty contiguous name segment between U+202E (RLO) and U+202C (PDF), preserving the segment's logical order | 4 names (trusted 7, tealeaves 9, monsoon 7, puppeteer 9) x {http, https}; 146 segments | 146 x 2 = **292** |
| A7-2 | Insert U+202E before a suffix of the name and reverse that suffix (no U+202C) | 32 suffix starts x 2 schemes | **64** |
| **A7 total** | | | **356** |

## Totals

| Technique | Constructions | Targets each | Trials if full run |
|---|---:|---:|---:|
| A1 | 1,308 | 27 | 35,316 |
| A2 | 63,488 | 27 | 1,714,176 |
| A3 | 114 | 14 | 1,596 |
| A4 | 11,004 | 14 | 154,056 |
| A5 | 10 | 14 | 140 |
| A6 | 928 | 14 | 12,992 |
| A7 | 356 | 14 | 4,984 |
| **Total** | **77,208** | | **1,923,260** |

Per-pattern CSV: `data/catalog_counts.csv` (from `--emit`). Full deterministic
catalog: `data/catalog.jsonl.gz` (77,208 lines; entry_id, pattern, technique,
mr, targets, params, reference L1, attack_input L2, carrier, representation).
