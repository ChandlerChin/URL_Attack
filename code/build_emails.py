# -*- coding: utf-8 -*-
"""Build the paired test emails (reference + attack) for catalog entries.

Implements the paired-email convention of the paper (Section "Relations for
the Three Protection Objectives"): each test uses 2 emails that differ only in
the embedded link. L1 is the ordinary reference link; L2 is the attack input.

Carrier rules (matching the paper's technique descriptions):
  - A1-A2 (MR1): the reference is an explicit hyperlink (<a href>); the attack
    input is carried as non-anchor plain text (A1-1 keeps its container form:
    HTML comment / hidden span / combined).
  - A3-A7 (MR2/MR3): both reference and attack are explicit hyperlinks.
  - A6: each input uses one representation (Unicode or Punycode) consistently
    in its displayed link text and href.

Usage:
    python build_emails.py --entry-id A6-1-0001 [--out DIR]     # one pair
    python build_emails.py --samples --out eml_samples          # bundled subset
    python build_emails.py --catalog catalog.jsonl --ids-file ids.txt --out DIR
"""
import argparse
import html
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Redacted display samples; original measurement emails are not distributed.
RECIPIENT_PLACEHOLDER = 'redacted@example.com'
SENDER = 'redacted@example.com'

REF_BODY = '<p><a href="{url}">{url}</a></p><p>Please review the link above.</p>'


def _attack_body(entry):
    carrier = entry['carrier']
    url = entry['attack_input']
    if carrier == 'container':
        return entry['container_html'] + '<p>Please review the content above.</p>'
    if carrier == 'plain_text':
        # non-anchor plain text; HTML-escape only the markup-significant chars
        # so the rendered text equals the constructed input
        return '<p>%s</p><p>Please review the link above.</p>' % html.escape(url, quote=False)
    if carrier == 'html_anchor':
        return '<p><a href="%s">%s</a></p><p>Please review the link above.</p>' % (
            html.escape(url, quote=True), html.escape(url, quote=False))
    raise ValueError('unknown carrier: %r' % carrier)


def build_pair_bytes(entry, recipient=RECIPIENT_PLACEHOLDER, pair_token=None):
    """Return independently identifiable MIME messages with byte-preserved payloads.

    Base64 is a MIME transport encoding, not an extra URL mutation. Decoding the
    MIME body recovers the exact UTF-8 HTML, including NUL and CR/LF characters.
    """
    from email.message import EmailMessage
    from email.policy import SMTP
    import hashlib
    eid = entry['entry_id']
    token = pair_token or eid
    body_ref = REF_BODY.format(url=html.escape(entry['reference'], quote=True))
    body_att = _attack_body(entry)
    result = []
    for role, body in [('ref', body_ref), ('attack', body_att)]:
        msg = EmailMessage(policy=SMTP)
        msg['From'] = SENDER
        msg['To'] = recipient
        msg['Subject'] = 'Link sample %s' % eid
        unique = hashlib.sha256((token + '/' + role).encode('utf-8')).hexdigest()
        msg['Message-ID'] = '<%s@artifact.invalid>' % unique
        msg['X-Pair-Id'] = token
        msg['X-Attack-Pattern'] = entry['pattern']
        # set_payload(bytes) preserves embedded CR/LF/NUL; text set_content
        # would normalize newlines and change A1/A2 character constructions.
        msg.set_type('text/html')
        msg.set_param('charset', 'utf-8')
        msg.set_payload(body.encode('utf-8'))
        from email.encoders import encode_base64
        encode_base64(msg)
        result.append(msg.as_bytes())
    return tuple(result)


def build_pair_files(entry, out_dir, recipient=RECIPIENT_PLACEHOLDER, pair_token=None):
    os.makedirs(out_dir, exist_ok=True)
    eid = entry['entry_id']
    paths = [os.path.join(out_dir, eid + '.ref.eml'),
             os.path.join(out_dir, eid + '.attack.eml')]
    for path, content in zip(paths, build_pair_bytes(entry, recipient, pair_token)):
        with open(path, 'wb') as f:
            f.write(content)
    return tuple(paths)


def load_catalog(path):
    """Read a catalog JSONL (plain or .gz)."""
    import gzip
    path = os.fspath(path)
    opener = gzip.open if path.endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


# Bundled sample subset: representative constructions per technique
# (see eml_samples/INDEX.md for the per-file list).
SAMPLE_ENTRY_IDS = ['A1-1-0001', 'A1-2-0001', 'A1-3-0001', 'A1-4-0001', 'A1-5-0001', 'A1-1-0002', 'A1-2-0002', 'A1-4-0002', 'A1-5-0002', 'A1-1-0003', 'A2-0047', 'A2-0048', 'A2-0093', 'A2-0161', 'A2-8204', 'A2-8233', 'A2-8234', 'A2-12291', 'A2-63247', 'A2-63330', 'A3-1-0001', 'A3-2-0001', 'A3-3-0001', 'A3-4-0001', 'A3-1-0002', 'A3-2-0002', 'A3-3-0002', 'A3-4-0002', 'A3-1-0003', 'A3-2-0003', 'A4-1-0001', 'A4-2-0001', 'A4-3-0001', 'A4-4-0001', 'A4-5-0001', 'A4-6-0001', 'A4-1-0002', 'A4-2-0002', 'A4-3-0002', 'A4-4-0002', 'A5-1-0001', 'A5-2-0001', 'A5-3-0001', 'A5-4-0001', 'A5-1-0002', 'A5-2-0002', 'A5-3-0002', 'A5-4-0002', 'A5-1-0003', 'A5-3-0003', 'A6-1-0001', 'A6-3-0001', 'A6-2-0001', 'A6-4-0001', 'A6-1-0002', 'A6-3-0002', 'A6-2-0002', 'A6-4-0002', 'A6-1-0003', 'A6-3-0003', 'A7-1-0001', 'A7-2-0001', 'A7-1-0002', 'A7-2-0002', 'A7-1-0003', 'A7-2-0003', 'A7-1-0004', 'A7-2-0004', 'A7-1-0005', 'A7-2-0005']


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--catalog', default=None, help='catalog.jsonl(.gz) path')
    ap.add_argument('--entry-id', default=None, help='build one pair by entry_id')
    ap.add_argument('--ids-file', default=None, help='file with one entry_id per line')
    ap.add_argument('--samples', action='store_true', help='build the bundled sample subset')
    ap.add_argument('--out', default='eml_out', help='output directory')
    ap.add_argument('--all', action='store_true', help='all catalog entries')
    ap.add_argument('--zip', dest='zip_path', help='write EML pairs into one archive instead of individual files')
    args = ap.parse_args()
    if sum(bool(x) for x in (args.entry_id, args.ids_file, args.samples, args.all)) != 1:
        ap.error('use exactly one of --entry-id, --ids-file, --samples or --all')

    catalog_path = args.catalog or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'catalog.jsonl.gz')
    catalog = load_catalog(catalog_path)
    by_id = {e['entry_id']: e for e in catalog}

    if args.all:
        ids = [e['entry_id'] for e in catalog]
    elif args.samples:
        ids = SAMPLE_ENTRY_IDS
    elif args.entry_id:
        ids = [args.entry_id]
    else:
        with open(args.ids_file, encoding='utf-8') as f:
            ids = [ln.strip() for ln in f if ln.strip()]

    for eid in ids:
        if eid not in by_id:
            raise SystemExit('entry not found in catalog: %s' % eid)
    if args.zip_path:
        from pathlib import Path
        import zipfile
        dest = Path(args.zip_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(dest, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for index, eid in enumerate(ids, 1):
                for role, raw in zip(('ref', 'attack'), build_pair_bytes(by_id[eid])):
                    info = zipfile.ZipInfo(eid + '.' + role + '.eml')
                    info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, raw)
                if index % 5000 == 0:
                    print('built %s/%s pairs' % (index, len(ids)), flush=True)
            archive.writestr('INPUTS_MANIFEST.json', json.dumps({
                'kind': 'generated paired test inputs; no attack results',
                'construction_entries': len(ids), 'eml_files': 2*len(ids),
                'date_header': 'omitted in display samples',
                'catalog': os.path.basename(catalog_path)}, indent=2))
        print('wrote %d EML files to %s' % (2*len(ids), dest))
    else:
        for eid in ids:
            build_pair_files(by_id[eid], args.out)
        print('wrote %d EML files to %s' % (2*len(ids), args.out))



if __name__ == '__main__':
    main()
