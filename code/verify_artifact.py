"""Offline integrity and sample checks; never contacts a target."""
import base64
import hashlib
import py_compile
import tempfile
from collections import Counter
from email import policy
from email.parser import BytesParser
from pathlib import Path
from build_emails import load_catalog, build_pair_bytes, SAMPLE_ENTRY_IDS
from construct_pairs import build_catalog
from algorithm_flow import algorithm1, algorithm2, TargetExecutionUnavailable
from prepare_eml import prepare


def main():
    root = Path(__file__).resolve().parent.parent
    catalog = load_catalog(root / 'data/catalog.jsonl.gz')
    assert len(catalog) == 77208
    assert catalog == build_catalog(), 'catalog differs from construction code'
    by_id = {e['entry_id']: e for e in catalog}
    assert len(by_id) == len(catalog)
    counts = Counter(by_id[i]['technique'] for i in SAMPLE_ENTRY_IDS)
    assert counts == {f'A{i}': 10 for i in range(1, 8)}
    assert len({by_id[i]['pattern'] for i in SAMPLE_ENTRY_IDS}) == 26
    assert len(list((root / 'eml_samples').glob('*.eml'))) == 140
    with tempfile.TemporaryDirectory() as tmp:
        for script in (root / 'code').glob('*.py'):
            py_compile.compile(str(script), cfile=str(Path(tmp) / (script.name + 'c')), doraise=True)
        for eid in SAMPLE_ENTRY_IDS:
            for role, expected in zip(('ref', 'attack'), build_pair_bytes(by_id[eid])):
                path = root / 'eml_samples' / (eid + '.' + role + '.eml')
                raw = path.read_bytes()
                assert raw == expected, path.name
                rest = raw.replace(b'\r\n', b'')
                assert b'\r' not in rest and b'\n' not in rest
                assert max(map(len, raw.split(b'\r\n'))) <= 998
                msg = BytesParser(policy=policy.default).parsebytes(raw)
                assert not msg.defects
                assert msg['From'] == msg['To'] == 'redacted@example.com'
                assert msg['Date'] is None
                assert msg.get_content_type() == 'text/html'
                assert msg['Content-Transfer-Encoding'] == 'base64'
                body = raw.split(b'\r\n\r\n', 1)[1]
                assert all(len(line) <= 76 for line in body.split(b'\r\n'))
                assert base64.b64decode(b''.join(body.split()), validate=True) == msg.get_payload(decode=True)
                out = Path(tmp) / path.name
                prepare(path, 'redacted@example.com', 'redacted@example.com', out)
                ready = BytesParser(policy=policy.default).parsebytes(out.read_bytes())
                assert ready['Date'] and ready.get_payload(decode=True) == msg.get_payload(decode=True)
    for flow in (algorithm1, algorithm2):
        try:
            flow([{}], {})
        except TargetExecutionUnavailable:
            pass
        else:
            raise AssertionError('target execution must be unavailable')
    for line in (root / 'SHA256SUMS').read_text(encoding='utf-8').splitlines():
        digest, name = line.split('  ', 1)
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
    print('PASS: 77,208 entries; 26 patterns; 140 redacted EMLs without Date; CRLF/MIME/body preservation; core syntax; target execution disabled; file hashes.')


if __name__ == '__main__':
    main()
