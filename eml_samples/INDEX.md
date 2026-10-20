# Redacted email sample index

Each technique provides 10 attack emails and 10 paired reference emails: 70 attack samples + 70 references = 140 EML files.
These examples cover all 26 patterns, have no Date header, and contain no recorded success/failure outcomes.
Original measurement emails are not distributed; these are redacted display samples.
The full 77,208-pair archive is retained separately for private retesting, not included in this public sample set.

| Technique | Entry ID | Pattern | Construction parameters |
|---|---|---|---|
| A1 | A1-1-0001 | A1-1 | comment only |
| A1 | A1-2-0001 | A1-2 | replace slashes at positions [0] with U+FF0F |
| A1 | A1-3-0001 | A1-3 | scheme-less domain, plain text in <p> |
| A1 | A1-4-0001 | A1-4 | U+0009 at colon_after, run_length=1 |
| A1 | A1-5-0001 | A1-5 | U+200B at colon_after, run_length=1 |
| A1 | A1-1-0002 | A1-1 | hidden span only |
| A1 | A1-2-0002 | A1-2 | replace slashes at positions [1] with U+FF0F |
| A1 | A1-4-0002 | A1-4 | U+0009 at colon_after, run_length=2 |
| A1 | A1-5-0002 | A1-5 | U+200B at colon_after, run_length=2 |
| A1 | A1-1-0003 | A1-1 | combined containers |
| A2 | A2-0047 | A2 | delimiter U+002E |
| A2 | A2-0048 | A2 | delimiter U+002F |
| A2 | A2-0093 | A2 | delimiter U+005C |
| A2 | A2-0161 | A2 | delimiter U+00A0 |
| A2 | A2-8204 | A2 | delimiter U+200B |
| A2 | A2-8233 | A2 | delimiter U+2028 |
| A2 | A2-8234 | A2 | delimiter U+2029 |
| A2 | A2-12291 | A2 | delimiter U+3002 |
| A2 | A2-63247 | A2 | delimiter U+FF0E |
| A2 | A2-63330 | A2 | delimiter U+FF61 |
| A3 | A3-1-0001 | A3-1 | boundary=0, char='-', repeat=1 |
| A3 | A3-2-0001 | A3-2 | within-label repetition x2 |
| A3 | A3-3-0001 | A3-3 | prefix depth 0 (labels: ['(none)']) |
| A3 | A3-4-0001 | A3-4 | suffix .co |
| A3 | A3-1-0002 | A3-1 | boundary=0, char='-', repeat=2 |
| A3 | A3-2-0002 | A3-2 | within-label repetition x3 |
| A3 | A3-3-0002 | A3-3 | prefix depth 1 (labels: ['login']) |
| A3 | A3-4-0002 | A3-4 | suffix .br |
| A3 | A3-1-0003 | A3-1 | boundary=0, char='-', repeat=3 |
| A3 | A3-2-0003 | A3-2 | within-label repetition x4 |
| A4 | A4-1-0001 | A4-1 | userinfo @ at encoding depth 2 (%2540) |
| A4 | A4-2-0001 | A4-2 | encoded positions [0] |
| A4 | A4-3-0001 | A4-3 | query-only, j=1 |
| A4 | A4-4-0001 | A4-4 | trusted name at path segment 1 |
| A4 | A4-5-0001 | A4-5 | path position, inserted [U+00AD] (len 1) |
| A4 | A4-6-0001 | A4-6 | userinfo separator: literal @ |
| A4 | A4-1-0002 | A4-1 | userinfo @ at encoding depth 3 (%252540) |
| A4 | A4-2-0002 | A4-2 | encoded positions [1] |
| A4 | A4-3-0002 | A4-3 | fragment-only, j=1 |
| A4 | A4-4-0002 | A4-4 | trusted name at path segment 2 |
| A5 | A5-1-0001 | A5-1 | chain: trusted subdomain entry -> external hop -> attacker |
| A5 | A5-2-0001 | A5-2 | open redirect on trusted main domain (url parameter) |
| A5 | A5-3-0001 | A5-3 | destination parameter target= |
| A5 | A5-4-0001 | A5-4 | search-service redirector, entry form /url?q= |
| A5 | A5-1-0002 | A5-1 | chain: trusted entry -> hop1 -> hop2 -> attacker (3 hops) |
| A5 | A5-2-0002 | A5-2 | open redirect on trusted subdomain (goto parameter) |
| A5 | A5-3-0002 | A5-3 | destination parameter continue= |
| A5 | A5-4-0002 | A5-4 | search-service redirector, entry form /link?u= |
| A5 | A5-1-0003 | A5-1 | chain: trusted main-domain entry -> trusted subdomain entry -> attacker |
| A5 | A5-3-0003 | A5-3 | destination parameter next= |
| A6 | A6-1-0001 | A6-1 | base=tealeaves, substitutions at [7], Unicode representation |
| A6 | A6-3-0001 | A6-3 | base=tealeaves, substitutions at [7], Unicode representation |
| A6 | A6-2-0001 | A6-2 | base=tealeaves, substitutions at [5, 7], Unicode representation |
| A6 | A6-4-0001 | A6-4 | base=tealeaves, substitutions at [5, 7], Unicode representation |
| A6 | A6-1-0002 | A6-1 | base=tealeaves, substitutions at [7], Punycode representation |
| A6 | A6-3-0002 | A6-3 | base=tealeaves, substitutions at [7], Punycode representation |
| A6 | A6-2-0002 | A6-2 | base=tealeaves, substitutions at [5, 7], Punycode representation |
| A6 | A6-4-0002 | A6-4 | base=tealeaves, substitutions at [5, 7], Punycode representation |
| A6 | A6-1-0003 | A6-1 | base=tealeaves, substitutions at [5], Unicode representation |
| A6 | A6-3-0003 | A6-3 | base=tealeaves, substitutions at [5], Unicode representation |
| A7 | A7-1-0001 | A7-1 | name=trusted, segment [0,0], scheme http (terminated run) |
| A7 | A7-2-0001 | A7-2 | name=trusted, suffix start 0, scheme http (unterminated run) |
| A7 | A7-1-0002 | A7-1 | name=trusted, segment [0,1], scheme http (terminated run) |
| A7 | A7-2-0002 | A7-2 | name=trusted, suffix start 1, scheme http (unterminated run) |
| A7 | A7-1-0003 | A7-1 | name=trusted, segment [0,2], scheme http (terminated run) |
| A7 | A7-2-0003 | A7-2 | name=trusted, suffix start 2, scheme http (unterminated run) |
| A7 | A7-1-0004 | A7-1 | name=trusted, segment [0,3], scheme http (terminated run) |
| A7 | A7-2-0004 | A7-2 | name=trusted, suffix start 3, scheme http (unterminated run) |
| A7 | A7-1-0005 | A7-1 | name=trusted, segment [0,4], scheme http (terminated run) |
| A7 | A7-2-0005 | A7-2 | name=trusted, suffix start 4, scheme http (unterminated run) |
