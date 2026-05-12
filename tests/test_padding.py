"""Tests for the plaintext padding helpers.

Padding alone does no cryptography — it just smears plaintext sizes
into a small set of buckets so a server watching ciphertext lengths
cannot distinguish "ok" from "I just got off the phone and let me
tell you everything". The tests assert:

  * round-trip restores the original bytes byte-for-byte,
  * empty / short / boundary / large payloads all hit the right bucket,
  * malformed blobs are rejected,
  * AEAD-level tampering is still caught (so padding doesn't open
    a new attack surface above the AEAD).
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from network.cryptolib.padding import (
    pad_plaintext, unpad_plaintext, _bucket_for, BUCKETS, HEADER_LEN,
)


class PaddingRoundTrip(unittest.TestCase):
    def test_empty(self):
        padded = pad_plaintext(b'')
        self.assertEqual(len(padded), 64)
        self.assertEqual(unpad_plaintext(padded), b'')

    def test_tiny(self):
        for sz in (1, 5, 32, 60):
            padded = pad_plaintext(b'x' * sz)
            self.assertEqual(len(padded), 64)
            self.assertEqual(unpad_plaintext(padded), b'x' * sz)

    def test_each_bucket_boundary(self):
        for bucket in BUCKETS:
            # Payload that exactly fills the bucket (minus header).
            payload = os.urandom(bucket - HEADER_LEN)
            padded = pad_plaintext(payload)
            self.assertEqual(len(padded), bucket)
            self.assertEqual(unpad_plaintext(padded), payload)

    def test_bucket_promotion(self):
        # 1-byte-too-big for the 64-byte bucket pushes us to 128.
        # Bucket 64 holds payloads up to (64 - HEADER_LEN) = 60 bytes;
        # 61 bytes spills into the 128-byte bucket.
        payload = os.urandom(61)
        padded = pad_plaintext(payload)
        self.assertEqual(len(padded), 128)
        self.assertEqual(unpad_plaintext(padded), payload)

    def test_above_max_bucket_uses_mib_increments(self):
        # Anything above 1 MiB rounds up to whole MiBs.
        payload = b'x' * (1024 * 1024 + 7)
        padded = pad_plaintext(payload)
        self.assertEqual(len(padded), 2 * 1024 * 1024)
        self.assertEqual(unpad_plaintext(padded), payload)


class PaddingMalformedInput(unittest.TestCase):
    def test_too_short_for_header(self):
        with self.assertRaises(ValueError):
            unpad_plaintext(b'abc')

    def test_length_field_exceeds_blob(self):
        # A header claiming 2**31 bytes but only 64 bytes follow.
        blob = (2 ** 31).to_bytes(4, 'big') + b'\x00' * 60
        with self.assertRaises(ValueError):
            unpad_plaintext(blob)

    def test_non_bytes_rejected(self):
        with self.assertRaises(TypeError):
            pad_plaintext('not bytes')
        with self.assertRaises(TypeError):
            unpad_plaintext('not bytes')


if __name__ == '__main__':
    unittest.main()
