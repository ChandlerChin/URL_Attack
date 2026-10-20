"""Prepare one EML for an authorized sender/recipient; never sends mail."""
import argparse
from email import policy
from email.parser import BytesParser
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path


def address(value):
    if any(c in value for c in ('\r', '\n')):
        raise ValueError('address must not contain header line breaks')
    parsed = parseaddr(value)[1]
    if parsed != value or parsed.count('@') != 1 or not all(parsed.split('@')):
        raise ValueError('provide one plain mailbox address')
    return parsed


def prepare(source, sender, recipient, destination):
    sender, recipient = address(sender), address(recipient)
    msg = BytesParser(policy=policy.SMTP).parsebytes(Path(source).read_bytes())
    if msg.is_multipart():
        raise ValueError('this preparer accepts the released single-part HTML samples')
    before = msg.get_payload(decode=True)
    for key, value in [('From', sender), ('To', recipient),
                       ('Date', formatdate(localtime=False)),
                       ('Message-ID', make_msgid(domain=sender.split('@')[1]))]:
        if key in msg:
            msg.replace_header(key, value)
        else:
            msg[key] = value
    raw = msg.as_bytes(policy=policy.SMTP)
    decoded = BytesParser(policy=policy.default).parsebytes(raw)
    if decoded.defects or decoded.get_payload(decode=True) != before:
        raise ValueError('MIME body changed during preparation')
    out = Path(destination)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('xb') as f:
        f.write(raw)
    return out


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', required=True)
    ap.add_argument('--sender', required=True)
    ap.add_argument('--recipient', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    print('Prepared EML; no mail sent:', prepare(args.input, args.sender, args.recipient, args.out))
