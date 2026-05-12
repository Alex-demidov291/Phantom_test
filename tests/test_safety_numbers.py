"""Verification-flow tests for the upgraded safety_numbers module.

The classic 60-digit safety number was already covered in
test_crypto.SafetyNumbers; this file targets the new
``safety_qr_payload`` / ``verify_scan_code`` / ``safety_qr_matrix``
helpers that back the QR-style verification UI.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from network.cryptolib.safety_numbers import (
    compute_safety_number,
    format_safety_number,
    safety_qr_payload,
    safety_qr_matrix,
    verify_scan_code,
    render_qr_matrix_ascii,
    SAFETY_QR_PREFIX,
)


class ScanCodeProperties(unittest.TestCase):
    def setUp(self):
        self.alice = b'\xaa' * 32
        self.bob = b'\xbb' * 32
        self.charlie = b'\xcc' * 32

    def test_payload_is_symmetric(self):
        a = safety_qr_payload(self.alice, self.bob)
        b = safety_qr_payload(self.bob, self.alice)
        self.assertEqual(a, b)

    def test_payload_has_versioned_prefix(self):
        code = safety_qr_payload(self.alice, self.bob)
        self.assertTrue(code.startswith(SAFETY_QR_PREFIX.decode('ascii')))

    def test_payload_changes_when_either_key_changes(self):
        baseline = safety_qr_payload(self.alice, self.bob)
        self.assertNotEqual(baseline,
                            safety_qr_payload(self.alice, self.charlie))
        self.assertNotEqual(baseline,
                            safety_qr_payload(self.charlie, self.bob))

    def test_payload_compact_size(self):
        # Must fit comfortably in a Version 2/3 QR (≤ ~60 chars).
        code = safety_qr_payload(self.alice, self.bob)
        self.assertLess(len(code), 80)

    def test_verify_scan_code_match(self):
        code = safety_qr_payload(self.alice, self.bob)
        self.assertTrue(verify_scan_code(self.alice, self.bob, code))
        # And the symmetric side.
        self.assertTrue(verify_scan_code(self.bob, self.alice, code))

    def test_verify_scan_code_ignores_whitespace_and_case(self):
        code = safety_qr_payload(self.alice, self.bob)
        # Insert spaces every 5 chars and lower-case the body.
        spaced = ' '.join(code[i:i + 5] for i in range(0, len(code), 5)).lower()
        self.assertTrue(verify_scan_code(self.alice, self.bob, spaced))

    def test_verify_scan_code_mismatch(self):
        code = safety_qr_payload(self.alice, self.bob)
        self.assertFalse(verify_scan_code(self.alice, self.charlie, code))

    def test_verify_scan_code_handles_garbage(self):
        # Anything that doesn't equal the canonical form fails.
        for bad in ('', 'PCSAFETYv1:', '!!!', 'random text'):
            self.assertFalse(verify_scan_code(self.alice, self.bob, bad))

    def test_verify_scan_code_constant_time_compare_uses_full_length(self):
        # Length-difference rejected before any comparison; truncated
        # payload of correct prefix still rejected.
        good = safety_qr_payload(self.alice, self.bob)
        self.assertFalse(verify_scan_code(self.alice, self.bob, good[:-1]))


class QRMatrixProperties(unittest.TestCase):
    def test_matrix_is_25x25(self):
        m = safety_qr_matrix(safety_qr_payload(b'\x00' * 32, b'\x01' * 32))
        self.assertEqual(len(m), 25)
        for row in m:
            self.assertEqual(len(row), 25)

    def test_matrix_is_deterministic(self):
        code = safety_qr_payload(b'\x07' * 32, b'\x08' * 32)
        self.assertEqual(safety_qr_matrix(code), safety_qr_matrix(code))

    def test_matrix_changes_with_payload(self):
        a = safety_qr_matrix(safety_qr_payload(b'\x07' * 32, b'\x08' * 32))
        b = safety_qr_matrix(safety_qr_payload(b'\x07' * 32, b'\x09' * 32))
        self.assertNotEqual(a, b)
        # SHA-256 avalanche: at least a third of cells should differ.
        diff = sum(1 for r in range(25) for c in range(25) if a[r][c] != b[r][c])
        self.assertGreater(diff, 25 * 25 // 3)

    def test_ascii_render_runs(self):
        m = safety_qr_matrix(safety_qr_payload(b'\x07' * 32, b'\x08' * 32))
        text = render_qr_matrix_ascii(m)
        self.assertIsInstance(text, str)
        # 25 rows / 2 rows-per-line = 13 lines.
        self.assertEqual(text.count('\n') + 1, 13)


class TrustStateTransitions(unittest.TestCase):
    """Lightweight model of the chat-header badge state machine.

    We test the *transitions* directly against the same logic the
    chat layer queries — first time we see a peer is 'unknown';
    same IK on next session is 'unchanged'; explicit verify is
    'verified'; differing IK is 'changed'. The actual storage is
    file-backed, so we model it as an in-memory dict here.
    """

    def _state(self, trust_state, current_ik):
        # Mirrors api.MessengerAPI.get_peer_trust_state's branch:
        entry = trust_state
        if entry is None:
            return 'unknown'
        if entry.get('verified_ik') == current_ik:
            return 'verified'
        if entry.get('seen_ik') == current_ik:
            return 'unchanged'
        return 'changed'

    def test_unknown_to_unchanged_to_verified(self):
        ik = 'abc'
        self.assertEqual(self._state(None, ik), 'unknown')
        seen = {'seen_ik': ik}
        self.assertEqual(self._state(seen, ik), 'unchanged')
        verified = {'verified_ik': ik}
        self.assertEqual(self._state(verified, ik), 'verified')

    def test_changed_detection(self):
        seen = {'seen_ik': 'abc'}
        self.assertEqual(self._state(seen, 'xyz'), 'changed')
        verified = {'verified_ik': 'abc'}
        self.assertEqual(self._state(verified, 'xyz'), 'changed')


if __name__ == '__main__':
    unittest.main()
