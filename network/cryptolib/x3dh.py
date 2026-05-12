import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from network.cryptolib.identity import IdentityKeys
from network.cryptolib.primitives import hkdf

X3DH_INFO = b'PhantomChats/X3DH/v1'

class X3DHError(Exception):
    pass


def _x25519_pub(b):
    return x25519.X25519PublicKey.from_public_bytes(b)


def _x25519_priv(b):
    return x25519.X25519PrivateKey.from_private_bytes(b)


def _pub_bytes(priv):
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _derive_sk(dh_outputs):
    f = b'\xff' * 32
    ikm = f + b''.join(dh_outputs)
    return hkdf(ikm=ikm, salt=b'\x00' * 32, info=X3DH_INFO, length=32)


def build_initial_message(initiator_identity, peer_bundle):
    ik_b = base64.b64decode(peer_bundle['ik'])
    sik_b = base64.b64decode(peer_bundle['sik'])
    spk_b = base64.b64decode(peer_bundle['spk'])
    spk_sig = base64.b64decode(peer_bundle['spk_signature'])
    identity_sig = base64.b64decode(peer_bundle['identity_signature'])

    if not IdentityKeys.verify_signature(sik_b, ik_b, identity_sig):
        raise X3DHError('peer identity signature invalid (IK does not match SIK)')
    if not IdentityKeys.verify_signature(sik_b, spk_b, spk_sig):
        raise X3DHError('peer signed-prekey signature invalid')

    ek_priv = x25519.X25519PrivateKey.generate()
    ek_pub_bytes = _pub_bytes(ek_priv)
    dh1 = initiator_identity.ik_priv.exchange(_x25519_pub(spk_b))
    dh2 = ek_priv.exchange(_x25519_pub(ik_b))
    dh3 = ek_priv.exchange(_x25519_pub(spk_b))
    dh_list = [dh1, dh2, dh3]
    opk_b64 = peer_bundle.get('opk')
    if opk_b64:
        opk_b = base64.b64decode(opk_b64)
        dh4 = ek_priv.exchange(_x25519_pub(opk_b))
        dh_list.append(dh4)

    sk = _derive_sk(dh_list)
    ad = initiator_identity.ik_pub_bytes + ik_b

    header = {
        'ik': base64.b64encode(initiator_identity.ik_pub_bytes).decode(),
        'sik': base64.b64encode(initiator_identity.sik_pub_bytes).decode(),
        'identity_signature': base64.b64encode(
            initiator_identity.sign_identity_binding()
        ).decode(),
        'ek': base64.b64encode(ek_pub_bytes).decode(),
        'spk_id': peer_bundle['spk_id'],
        'opk_id': peer_bundle.get('opk_id'),
    }

    return sk, ad, header, spk_b


def accept_initial_message(responder_identity, prekey_store, header):
    ik_a = base64.b64decode(header['ik'])
    sik_a = base64.b64decode(header['sik'])
    ek_a = base64.b64decode(header['ek'])
    identity_sig = base64.b64decode(header['identity_signature'])
    spk_id = header['spk_id']
    opk_id = header.get('opk_id')

    if not IdentityKeys.verify_signature(sik_a, ik_a, identity_sig):
        raise X3DHError('initiator identity signature invalid')

    spk = prekey_store.get_signed_prekey_by_id(spk_id)
    if spk is None:
        raise X3DHError(f'unknown signed prekey id={spk_id}')
    spk_priv = _x25519_priv(spk.priv_bytes)
    dh1 = spk_priv.exchange(_x25519_pub(ik_a))
    dh2 = responder_identity.ik_priv.exchange(_x25519_pub(ek_a))
    dh3 = spk_priv.exchange(_x25519_pub(ek_a))

    dh_list = [dh1, dh2, dh3]
    consumed_opk_id = None
    if opk_id is not None:
        opk = prekey_store.take_one_time_prekey(opk_id)
        if opk is None:
            raise X3DHError(f'unknown one-time prekey id={opk_id}')
        opk_priv = _x25519_priv(opk.priv_bytes)
        dh4 = opk_priv.exchange(_x25519_pub(ek_a))
        dh_list.append(dh4)
        consumed_opk_id = opk_id

    sk = _derive_sk(dh_list)
    ad = ik_a + responder_identity.ik_pub_bytes
    return sk, ad, ik_a, sik_a, consumed_opk_id, spk.pub_bytes
