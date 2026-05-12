import struct


BUCKETS = (
    64, 128, 256, 512, 1024, 2048, 4096,
    8192, 16384, 32768, 65536, 131072,
    262144, 524288, 1048576,
)
HEADER_LEN = 4
MIB = 1024 * 1024
MAX_LEN = (1 << 32) - 1


def _bucket_for(length):
    if length < 0 or length > MAX_LEN:
        raise ValueError('plaintext length out of range')
    needed = length + HEADER_LEN
    for b in BUCKETS:
        if b >= needed:
            return b
    return ((needed + MIB - 1) // MIB) * MIB


def pad_plaintext(payload):
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError('payload must be bytes')
    if len(payload) > MAX_LEN:
        raise ValueError('payload too large to pad')
    bucket = _bucket_for(len(payload))
    header = struct.pack('>I', len(payload))
    body = bytes(payload)
    pad = b'\x00' * (bucket - len(header) - len(body))
    return header + body + pad


def unpad_plaintext(blob):
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError('blob must be bytes')
    if len(blob) < HEADER_LEN:
        raise ValueError('padded blob too short for length header')
    (length,) = struct.unpack('>I', bytes(blob[:HEADER_LEN]))
    if length + HEADER_LEN > len(blob):
        raise ValueError('declared length exceeds blob size')
    return bytes(blob[HEADER_LEN:HEADER_LEN + length])
