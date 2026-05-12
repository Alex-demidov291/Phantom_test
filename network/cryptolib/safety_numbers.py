import base64
import hashlib
import hmac


SAFETY_VERSION = b'\x00\x00'
SAFETY_ITERATIONS = 5200
SAFETY_FINGERPRINT_LEN = 30
SAFETY_QR_PREFIX = b'PCSAFETYv1:'  # domain-separation tag for QR payloads


def _fingerprint(public_key_bytes, version=SAFETY_VERSION,
                 iterations=SAFETY_ITERATIONS):
    h = version + public_key_bytes + public_key_bytes
    for _ in range(iterations):
        h = hashlib.sha512(h + public_key_bytes).digest()
    return h[:SAFETY_FINGERPRINT_LEN]


def _digits_from(bytes_30):
    digits = []
    for i in range(0, 30, 5):
        chunk = int.from_bytes(bytes_30[i:i + 5], 'big')
        digits.append(f'{chunk % 100000:05d}')
    return digits


def _validate_pair(own_ik_pub_bytes, peer_ik_pub_bytes):
    if (not isinstance(own_ik_pub_bytes, (bytes, bytearray))
            or len(own_ik_pub_bytes) != 32):
        raise ValueError('own IK must be 32 bytes')
    if (not isinstance(peer_ik_pub_bytes, (bytes, bytearray))
            or len(peer_ik_pub_bytes) != 32):
        raise ValueError('peer IK must be 32 bytes')


def _ordered_pair(own_ik_pub_bytes, peer_ik_pub_bytes):
    a = bytes(own_ik_pub_bytes)
    b = bytes(peer_ik_pub_bytes)
    return (a, b) if a < b else (b, a)


def _combined_fingerprint(own_ik_pub_bytes, peer_ik_pub_bytes):
    _validate_pair(own_ik_pub_bytes, peer_ik_pub_bytes)
    a, b = _ordered_pair(own_ik_pub_bytes, peer_ik_pub_bytes)
    fa = _fingerprint(a)
    fb = _fingerprint(b)
    return hashlib.sha512(b'PCSafety/Combined/v1|' + fa + b'|' + fb).digest()[:SAFETY_FINGERPRINT_LEN]


def compute_safety_number(own_ik_pub_bytes, peer_ik_pub_bytes):
    _validate_pair(own_ik_pub_bytes, peer_ik_pub_bytes)
    a = _fingerprint(bytes(own_ik_pub_bytes))
    b = _fingerprint(bytes(peer_ik_pub_bytes))
    if bytes(own_ik_pub_bytes) < bytes(peer_ik_pub_bytes):
        return _digits_from(a) + _digits_from(b)
    return _digits_from(b) + _digits_from(a)


def format_safety_number(chunks):
    if len(chunks) != 12:
        raise ValueError('expected 12 chunks')
    line1 = ' '.join(chunks[:6])
    line2 = ' '.join(chunks[6:])
    return f'{line1}\n{line2}'


def safety_qr_payload(own_ik_pub_bytes, peer_ik_pub_bytes):
    digest = _combined_fingerprint(own_ik_pub_bytes, peer_ik_pub_bytes)
    body = base64.b32encode(digest).decode('ascii').rstrip('=')
    return SAFETY_QR_PREFIX.decode('ascii') + body


def verify_scan_code(own_ik_pub_bytes, peer_ik_pub_bytes, candidate):
    if not isinstance(candidate, str):
        return False
    expected = safety_qr_payload(own_ik_pub_bytes, peer_ik_pub_bytes)
    cand = ''.join(candidate.split()).upper()
    exp = ''.join(expected.split()).upper()
    if len(cand) != len(exp):
        return False
    return hmac.compare_digest(cand.encode('ascii'), exp.encode('ascii'))


def safety_qr_matrix(payload, scale=1):
    digest = hashlib.sha256(payload.encode('utf-8')).digest()
    stream = b''
    counter = 0
    while len(stream) < 79:
        stream += hashlib.sha256(digest + counter.to_bytes(4, 'big')).digest()
        counter += 1
    rows = []
    for r in range(25):
        row = []
        for c in range(25):
            idx = r * 25 + c
            byte = stream[idx // 8]
            bit = (byte >> (idx % 8)) & 1
            row.append(bool(bit))
        rows.append(row)
    if scale > 1:
        rows = [
            [cell for cell in row for _ in range(scale)]
            for row in rows for _ in range(scale)
        ]
    return rows


def render_qr_matrix_ascii(rows):
    out_lines = []
    for r in range(0, len(rows), 2):
        line = []
        top = rows[r]
        bot = rows[r + 1] if r + 1 < len(rows) else [False] * len(top)
        for c in range(len(top)):
            t = top[c]
            b = bot[c]
            if t and b:
                line.append('█')
            elif t and not b:
                line.append('▀')
            elif not t and b:
                line.append('▄')
            else:
                line.append(' ')
        out_lines.append(''.join(line))
    return '\n'.join(out_lines)
