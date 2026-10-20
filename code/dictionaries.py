# -*- coding: utf-8 -*-
"""Character dictionaries and fixed name/label lists used by the construction catalog.

All dictionaries are FIXED: they are part of the frozen catalog definition in the
paper (Section "Input Construction and Mutation Strategies" and Appendix
"Mutation Parameter Details"). Do not modify them without re-deriving the counts.
"""

# --- A1-4 whitespace dictionary: Unicode White_Space=yes property set (25 chars) ---
WHITE_SPACE = [
    0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x0020, 0x0085, 0x00A0, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
    0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
]
assert len(WHITE_SPACE) == 25

# --- A4-5 format-character dictionary (15 chars, cf. Appendix "A4 Unicode dictionary") ---
FORMAT_CHARS = [
    0x00AD, 0x061C, 0x180E, 0x200B, 0x200C, 0x200D,
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
    0xFEFF, 0xFFF9, 0xFFFA, 0xFFFB,
]
assert len(FORMAT_CHARS) == 15

# --- A4-5 single-character insertion (tested separately, Appendix) ---
A4_5_EXTRA_CHARS = [0x2100]

# --- A6 homograph substitution maps (Appendix "A6 substitution assignments") ---
CYRILLIC_MAP = {'a': '\u0430', 'e': '\u0435', 'o': '\u043E'}
GREEK_MAP = {'a': '\u03B1', 'e': '\u03B5', 'p': '\u03C1'}

# A6 base names and the mutable positions of each name.
# Each mutable position lists its allowed counterparts (None = keep Latin).
A6_NAMES = {
    'tealeaves': {2: ['cyrillic', 'greek'], 5: ['cyrillic', 'greek'],      # a, a
                  1: ['cyrillic', 'greek'], 4: ['cyrillic', 'greek'], 7: ['cyrillic', 'greek']},  # e, e, e
    'monsoon':   {1: ['cyrillic'], 4: ['cyrillic'], 5: ['cyrillic']},      # o, o, o
    'puppeteer': {0: ['greek'], 2: ['greek'], 3: ['greek'],                # p, p, p
                  4: ['cyrillic', 'greek'], 6: ['cyrillic', 'greek'], 7: ['cyrillic', 'greek']},  # e, e, e
}

# --- A3-3 fixed ordered prefix-label list (depths 1-8; depth 0 uses no prefix) ---
A3_PREFIX_LABELS = ['login', 'secure', 'account', 'mail', 'auth', 'my', 'www', 'signin']

# --- A3-4 selected suffix list (11 suffixes; original .com is not among them) ---
A3_SUFFIXES = ['.co', '.br', '.co.uk', '.com.br', '.org', '.net', '.io', '.dev',
               '.co.jp', '.com.cn', '.app']

# --- A4-4 fixed filler path segments (trusted token replaces exactly one of 8 positions) ---
A4_PATH_SEGMENTS = ['docs', 'img', 'assets', 'static', 'login', 'api', 'help', 'view']

# --- A4-3 fixed query fields and fragment segments (4 positions indexed by j = 1..4) ---
A4_QUERY_FIELDS = ['p1', 'p2', 'p3', 'p4']
A4_QUERY_FILLER = 'filler'
A4_FRAGMENT_SEGMENTS = ['s1', 's2', 's3', 's4']

# --- A7 base names (lengths 7, 9, 7, 9) ---
A7_NAMES = ['trusted', 'tealeaves', 'monsoon', 'puppeteer']
A7_SCHEMES = ['http', 'https']

# --- Role domains used by the paper's attack model (Section 3.1) ---
# These are ROLE NAMES. Before delivery each role must be mapped to an actually
# registered, attacker/trust-role-controlled test domain (see the external private domain configuration).
ATTACKER_HOST = 'www.malicious.com'
ATTACKER_ROOT = 'https://www.malicious.com/'
TRUSTED_HOST = 'www.whitelisted.com'
# A1 base URL for positional mutations: contains exactly three "/" separators
# (the two scheme slashes plus the path slash), cf. pattern A1-2.
A1_BASE_URL = 'https://www.malicious.com/page'
A1_HOST_LABEL = 'malicious'
A1_LABEL_BOUNDARY_HOST = 'www.malicious'  # insert before '.com' -> label boundary

# --- A5 role entries (placeholders; each must be registered and verified per
#     the paper's execution conditions before delivery) ---
A5_ATTCKER_DEST = 'https://www.malicious.com/'
A5_TRUSTED_SUB = 'sub.whitelisted.com'
A5_TRUSTED_MAIN = 'whitelisted.com'
