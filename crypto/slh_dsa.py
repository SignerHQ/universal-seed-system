# Copyright (c) 2026 Signer — MIT License

"""SLH-DSA-SHAKE-128s (SPHINCS+) — FIPS 205 post-quantum digital signature.

Pure-Python implementation of the Stateless Hash-Based Digital Signature
Standard at parameter set SLH-DSA-SHAKE-128s.

Security relies solely on the collision resistance of SHAKE-256 — no
lattice assumptions required. This is the most conservative post-quantum choice.

Key sizes:
    Public key:  32 bytes
    Secret key:  64 bytes
    Signature:   7,856 bytes

Security: NIST Level 1 (128-bit post-quantum security).
Assumption: Hash function (SHAKE-256) security only.

Reference: NIST FIPS 205 (August 2024).

Public API:
    slh_keygen(seed)              -> (sk_bytes, pk_bytes)
    slh_sign(msg, sk, ctx=b"")    -> sig_bytes    (pure FIPS 205)
    slh_verify(msg, sig, pk, ctx) -> bool          (pure FIPS 205)

Notes:
    - Messages are byte-aligned (Python bytes). Bit-level granularity is not
      supported (would require a bit-level SHAKE interface).
    - Signing defaults to hedged mode (addrnd generated via os.urandom) as
      recommended by FIPS 205. Pass deterministic=True for the deterministic
      variant (uses PK.seed as opt_rand).
    - NOT constant-time: Python branching and hash-call patterns may leak
      timing information. For deployments where side-channel attacks are a
      concern, use a vetted constant-time C/Rust implementation instead.
      SLH-DSA is inherently more side-channel-friendly than lattice schemes
      since its security rests on hash functions, not secret-dependent
      polynomial arithmetic.
"""

import hashlib
import os
import struct

# ── SLH-DSA-SHAKE-128s Parameters (FIPS 205 Table 2) ─────────────

_N = 16           # Security parameter (hash output bytes)
_FULL_H = 63           # Total tree height
_D = 7            # Number of hypertree layers
_HP = _FULL_H // _D  # = 9, height of each XMSS tree
_A = 12           # FORS tree height
_K = 14           # Number of FORS trees
_LG_W = 4         # Winternitz parameter log2
_W = 1 << _LG_W   # = 16, Winternitz parameter

# WOTS+ constants
# len1 = ceil(8*n / lg_w) = ceil(128/4) = 32 message blocks
_LEN1 = (8 * _N + _LG_W - 1) // _LG_W  # = 32
# len2 = floor(log_w(len1*(w-1))) + 1 = floor(log_16(480)) + 1 = 3
_LEN2 = 3
_LEN = _LEN1 + _LEN2  # = 35, total WOTS+ chains

# Message digest output: floor((k*a + 7)/8) + floor((h - h/d + 7)/8) + floor((h/d + 7)/8)
_MD_BYTES = (_K * _A + 7) // 8   # = 21
_IDX_TREE_BYTES = (_FULL_H - _HP + 7) // 8  # = 7
_IDX_LEAF_BYTES = (_HP + 7) // 8  # = 2
_M = _MD_BYTES + _IDX_TREE_BYTES + _IDX_LEAF_BYTES  # = 30

# Recalculate signature size:
# SIG = R(n) + SIG_FORS(k*(1+a)*n) + SIG_HT(d*(hp+len)*n)
# = 16 + 14*13*16 + 7*(9+35)*16 = 16 + 2912 + 4928 = 7856
_SIG_SIZE = _N + _K * (1 + _A) * _N + _D * (_HP + _LEN) * _N  # = 7856
_PK_SIZE = 2 * _N   # = 32
_SK_SIZE = 4 * _N   # = 64 (SK.seed + SK.prf + PK.seed + PK.root)


# ── ADRS (Address) Structure ──────────────────────────────────────
# 32-byte structured address identifying each node in the tree hierarchy.

# ADRS field offsets (FIPS 205 Section 4.2)
_ADRS_LAYER = 0         # Bytes 0-3: layer address
_ADRS_TREE = 4          # Bytes 4-15: tree address (96 bits)
_ADRS_TYPE = 16         # Bytes 16-19: address type
_ADRS_WORD1 = 20        # Bytes 20-23: type-specific word 1
_ADRS_WORD2 = 24        # Bytes 24-27: type-specific word 2
_ADRS_WORD3 = 28        # Bytes 28-31: type-specific word 3

# Address types
_ADRS_TYPE_WOTS_HASH = 0
_ADRS_TYPE_WOTS_PK = 1
_ADRS_TYPE_TREE = 2
_ADRS_TYPE_FORS_TREE = 3
_ADRS_TYPE_FORS_ROOTS = 4
_ADRS_TYPE_WOTS_PRF = 5
_ADRS_TYPE_FORS_PRF = 6


def _adrs_new():
    """Create a new zero-initialized ADRS."""
    return bytearray(32)


def _adrs_set_layer(adrs, layer):
    struct.pack_into(">I", adrs, _ADRS_LAYER, layer)


def _adrs_set_tree(adrs, tree):
    """Set 96-bit tree address (bytes 4-15) — toByte(tree, 12)."""
    adrs[_ADRS_TREE:_ADRS_TREE + 12] = tree.to_bytes(12, "big")


def _adrs_set_type(adrs, type_val):
    struct.pack_into(">I", adrs, _ADRS_TYPE, type_val)
    # Clear remaining words when type changes
    adrs[20:32] = b'\x00' * 12


def _adrs_set_keypair(adrs, kp):
    struct.pack_into(">I", adrs, _ADRS_WORD1, kp)


def _adrs_set_chain(adrs, chain):
    struct.pack_into(">I", adrs, _ADRS_WORD2, chain)


def _adrs_set_hash(adrs, hash_idx):
    struct.pack_into(">I", adrs, _ADRS_WORD3, hash_idx)


def _adrs_set_tree_height(adrs, height):
    struct.pack_into(">I", adrs, _ADRS_WORD2, height)


def _adrs_set_tree_index(adrs, index):
    struct.pack_into(">I", adrs, _ADRS_WORD3, index)


def _adrs_copy(adrs):
    return bytearray(adrs)


# ── Tweakable Hash Functions (SHAKE-256 based) ────────────────────

def _F(pk_seed, adrs, msg):
    """Tweakable hash: SHAKE-256(PK.seed || ADRS || msg, n).

    Single-block input (msg is n bytes).
    """
    return hashlib.shake_256(pk_seed + bytes(adrs) + msg).digest(_N)


def _H(pk_seed, adrs, m1_m2):
    """Tweakable hash: SHAKE-256(PK.seed || ADRS || m1||m2, n).

    Two-block input (m1_m2 is 2n bytes).
    """
    return hashlib.shake_256(pk_seed + bytes(adrs) + m1_m2).digest(_N)


def _T_l(pk_seed, adrs, msg):
    """Tweakable hash for variable-length input.

    SHAKE-256(PK.seed || ADRS || msg, n). msg is len*n bytes.
    """
    return hashlib.shake_256(pk_seed + bytes(adrs) + msg).digest(_N)


def _PRF(pk_seed, sk_seed, adrs):
    """Pseudorandom function: SHAKE-256(PK.seed || ADRS || SK.seed, n)."""
    return hashlib.shake_256(pk_seed + bytes(adrs) + sk_seed).digest(_N)


def _PRF_msg(sk_prf, opt_rand, msg):
    """Message PRF: SHAKE-256(SK.prf || opt_rand || msg, n)."""
    return hashlib.shake_256(sk_prf + opt_rand + msg).digest(_N)


def _H_msg(R, pk_seed, pk_root, msg):
    """Message hash: SHAKE-256(R || PK.seed || PK.root || msg, m)."""
    return hashlib.shake_256(R + pk_seed + pk_root + msg).digest(_M)


# ── WOTS+ One-Time Signatures ─────────────────────────────────────

def _wots_chain(X, start, steps, pk_seed, adrs):
    """Apply hash chain: F^steps starting from F^start.

    Algorithm 5, FIPS 205.
    """
    tmp = X
    for i in range(start, start + steps):
        _adrs_set_hash(adrs, i)
        tmp = _F(pk_seed, adrs, tmp)
    return tmp


def _wots_keygen(sk_seed, pk_seed, adrs):
    """Generate WOTS+ public key (Algorithm 6, FIPS 205).

    Returns the compressed public key (n bytes).
    """
    sk_adrs = _adrs_copy(adrs)
    _adrs_set_type(sk_adrs, _ADRS_TYPE_WOTS_PRF)
    _adrs_set_keypair(sk_adrs, struct.unpack_from(">I", adrs, _ADRS_WORD1)[0])

    chains = []
    for i in range(_LEN):
        _adrs_set_chain(sk_adrs, i)
        sk = _PRF(pk_seed, sk_seed, sk_adrs)
        chain_adrs = _adrs_copy(adrs)
        _adrs_set_chain(chain_adrs, i)
        chains.append(_wots_chain(sk, 0, _W - 1, pk_seed, chain_adrs))

    wots_pk_adrs = _adrs_copy(adrs)
    _adrs_set_type(wots_pk_adrs, _ADRS_TYPE_WOTS_PK)
    _adrs_set_keypair(wots_pk_adrs, struct.unpack_from(">I", adrs, _ADRS_WORD1)[0])
    return _T_l(pk_seed, wots_pk_adrs, b"".join(chains))


def _wots_sign(msg, sk_seed, pk_seed, adrs):
    """WOTS+ signing (Algorithm 7, FIPS 205).

    msg is n bytes. Returns signature (_LEN * n bytes).
    """
    # Convert message to base-w representation
    msg_base_w = _base_w(msg, _LEN1)
    csum = sum(_W - 1 - v for v in msg_base_w)
    csum <<= (8 - ((_LEN2 * _LG_W) % 8)) % 8
    csum_bytes = csum.to_bytes((_LEN2 * _LG_W + 7) // 8, "big")
    msg_base_w += _base_w(csum_bytes, _LEN2)

    sk_adrs = _adrs_copy(adrs)
    _adrs_set_type(sk_adrs, _ADRS_TYPE_WOTS_PRF)
    _adrs_set_keypair(sk_adrs, struct.unpack_from(">I", adrs, _ADRS_WORD1)[0])

    chains = []
    for i in range(_LEN):
        _adrs_set_chain(sk_adrs, i)
        sk = _PRF(pk_seed, sk_seed, sk_adrs)
        chain_adrs = _adrs_copy(adrs)
        _adrs_set_chain(chain_adrs, i)
        chains.append(_wots_chain(sk, 0, msg_base_w[i], pk_seed, chain_adrs))
    return b"".join(chains)


def _wots_pk_from_sig(sig, msg, pk_seed, adrs):
    """Recover WOTS+ public key from signature (Algorithm 8, FIPS 205)."""
    msg_base_w = _base_w(msg, _LEN1)
    csum = sum(_W - 1 - v for v in msg_base_w)
    csum <<= (8 - ((_LEN2 * _LG_W) % 8)) % 8
    csum_bytes = csum.to_bytes((_LEN2 * _LG_W + 7) // 8, "big")
    msg_base_w += _base_w(csum_bytes, _LEN2)

    chains = []
    for i in range(_LEN):
        chain_adrs = _adrs_copy(adrs)
        _adrs_set_chain(chain_adrs, i)
        sig_i = sig[i * _N:(i + 1) * _N]
        chains.append(_wots_chain(sig_i, msg_base_w[i], _W - 1 - msg_base_w[i], pk_seed, chain_adrs))

    wots_pk_adrs = _adrs_copy(adrs)
    _adrs_set_type(wots_pk_adrs, _ADRS_TYPE_WOTS_PK)
    _adrs_set_keypair(wots_pk_adrs, struct.unpack_from(">I", adrs, _ADRS_WORD1)[0])
    return _T_l(pk_seed, wots_pk_adrs, b"".join(chains))


def _base_w(data, out_len):
    """Convert byte string to base-w representation.

    For w=16 (lg_w=4): each byte yields 2 nibbles, high nibble first.
    """
    result = []
    for byte in data:
        result.append((byte >> 4) & 0x0F)
        result.append(byte & 0x0F)
        if len(result) >= out_len:
            break
    return result[:out_len]


# ── XMSS (Merkle Tree Signatures) ─────────────────────────────────

def _xmss_node(sk_seed, pk_seed, i, z, adrs):
    """Compute XMSS tree node at position i, height z (Algorithm 9, FIPS 205).

    Recursive: leaves are WOTS+ public keys, internal nodes are H(left||right).
    """
    if z == 0:
        # Leaf: WOTS+ public key
        wots_adrs = _adrs_copy(adrs)
        _adrs_set_type(wots_adrs, _ADRS_TYPE_WOTS_HASH)
        _adrs_set_keypair(wots_adrs, i)
        return _wots_keygen(sk_seed, pk_seed, wots_adrs)
    else:
        # Internal node: hash of children
        left = _xmss_node(sk_seed, pk_seed, 2 * i, z - 1, adrs)
        right = _xmss_node(sk_seed, pk_seed, 2 * i + 1, z - 1, adrs)
        node_adrs = _adrs_copy(adrs)
        _adrs_set_type(node_adrs, _ADRS_TYPE_TREE)
        _adrs_set_tree_height(node_adrs, z)
        _adrs_set_tree_index(node_adrs, i)
        return _H(pk_seed, node_adrs, left + right)


def _xmss_sign(msg, sk_seed, idx, pk_seed, adrs):
    """XMSS tree signing (Algorithm 10, FIPS 205).

    Returns: (sig_wots, auth_path) where auth_path is hp * n bytes.
    idx is the leaf index to sign with.
    """
    # WOTS+ signature of the message
    wots_adrs = _adrs_copy(adrs)
    _adrs_set_type(wots_adrs, _ADRS_TYPE_WOTS_HASH)
    _adrs_set_keypair(wots_adrs, idx)
    sig = _wots_sign(msg, sk_seed, pk_seed, wots_adrs)

    # Authentication path: sibling nodes from leaf to root
    auth_parts = []
    for j in range(_HP):
        sibling = idx ^ 1  # Sibling index at this level
        auth_parts.append(_xmss_node(sk_seed, pk_seed, sibling, j, adrs))
        idx >>= 1
    return sig, b"".join(auth_parts)


# ── Hypertree ──────────────────────────────────────────────────────

def _ht_sign(msg, sk_seed, pk_seed, idx_tree, idx_leaf):
    """Hypertree signing (Algorithm 11, FIPS 205).

    Signs msg at position (idx_tree, idx_leaf) through D layers.
    Returns HT signature: D * (WOTS_sig + auth_path).
    """
    adrs = _adrs_new()
    _adrs_set_layer(adrs, 0)
    _adrs_set_tree(adrs, idx_tree)

    sig_tmp, auth_tmp = _xmss_sign(msg, sk_seed, idx_leaf, pk_seed, adrs)
    ht_parts = [sig_tmp, auth_tmp]

    root = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, msg, pk_seed, adrs)

    for j in range(1, _D):
        idx_leaf = idx_tree % (1 << _HP)
        idx_tree >>= _HP
        adrs = _adrs_new()
        _adrs_set_layer(adrs, j)
        _adrs_set_tree(adrs, idx_tree)
        sig_tmp, auth_tmp = _xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs)
        ht_parts.append(sig_tmp)
        ht_parts.append(auth_tmp)
        if j < _D - 1:
            root = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, root, pk_seed, adrs)

    return b"".join(ht_parts)


def _ht_verify(msg, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root):
    """Hypertree verification (Algorithm 12, FIPS 205).

    Returns True if the HT signature is valid.
    """
    layer_sig_size = _LEN * _N + _HP * _N  # WOTS sig + auth path per layer
    adrs = _adrs_new()
    _adrs_set_layer(adrs, 0)
    _adrs_set_tree(adrs, idx_tree)

    offset = 0
    sig_tmp = sig_ht[offset:offset + _LEN * _N]
    offset += _LEN * _N
    auth_tmp = sig_ht[offset:offset + _HP * _N]
    offset += _HP * _N

    node = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, msg, pk_seed, adrs)

    for j in range(1, _D):
        idx_leaf = idx_tree % (1 << _HP)
        idx_tree >>= _HP
        adrs = _adrs_new()
        _adrs_set_layer(adrs, j)
        _adrs_set_tree(adrs, idx_tree)

        sig_tmp = sig_ht[offset:offset + _LEN * _N]
        offset += _LEN * _N
        auth_tmp = sig_ht[offset:offset + _HP * _N]
        offset += _HP * _N

        node = _xmss_root_from_sig(idx_leaf, sig_tmp, auth_tmp, node, pk_seed, adrs)

    return node == pk_root


def _xmss_root_from_sig(idx, sig, auth, msg, pk_seed, adrs):
    """Compute XMSS root from a signature and authentication path.

    Algorithm 10b / verification helper (FIPS 205).
    """
    # Recover WOTS+ public key
    wots_adrs = _adrs_copy(adrs)
    _adrs_set_type(wots_adrs, _ADRS_TYPE_WOTS_HASH)
    _adrs_set_keypair(wots_adrs, idx)
    node = _wots_pk_from_sig(sig, msg, pk_seed, wots_adrs)

    # Walk up the tree using auth path
    tree_adrs = _adrs_copy(adrs)
    _adrs_set_type(tree_adrs, _ADRS_TYPE_TREE)
    for j in range(_HP):
        _adrs_set_tree_height(tree_adrs, j + 1)
        auth_j = auth[j * _N:(j + 1) * _N]
        if (idx >> j) & 1 == 0:
            _adrs_set_tree_index(tree_adrs, idx >> (j + 1))
            node = _H(pk_seed, tree_adrs, node + auth_j)
        else:
            _adrs_set_tree_index(tree_adrs, idx >> (j + 1))
            node = _H(pk_seed, tree_adrs, auth_j + node)
    return node


# ── FORS (Forest of Random Subsets) ───────────────────────────────

def _fors_keygen(sk_seed, pk_seed, adrs, idx):
    """Generate FORS secret value at index idx."""
    fors_adrs = _adrs_copy(adrs)
    _adrs_set_type(fors_adrs, _ADRS_TYPE_FORS_PRF)
    _adrs_set_keypair(fors_adrs, struct.unpack_from(">I", adrs, _ADRS_WORD1)[0])
    _adrs_set_tree_index(fors_adrs, idx)
    return _PRF(pk_seed, sk_seed, fors_adrs)


def _fors_tree_node(sk_seed, pk_seed, adrs, i, z):
    """Compute FORS tree node at position i, height z (Algorithm 15, FIPS 205).

    Expects adrs already has type=FORS_TREE and keypair address set.
    """
    if z == 0:
        sk = _fors_keygen(sk_seed, pk_seed, adrs, i)
        node_adrs = _adrs_copy(adrs)
        _adrs_set_tree_height(node_adrs, 0)
        _adrs_set_tree_index(node_adrs, i)
        return _F(pk_seed, node_adrs, sk)

    left = _fors_tree_node(sk_seed, pk_seed, adrs, 2 * i, z - 1)
    right = _fors_tree_node(sk_seed, pk_seed, adrs, 2 * i + 1, z - 1)
    node_adrs = _adrs_copy(adrs)
    _adrs_set_tree_height(node_adrs, z)
    _adrs_set_tree_index(node_adrs, i)
    return _H(pk_seed, node_adrs, left + right)


def _fors_sign(md, sk_seed, pk_seed, adrs):
    """FORS signing (Algorithm 16, FIPS 205).

    md: message digest bytes to split into k a-bit indices.
    Returns: FORS signature (k * (1 + a) * n bytes).
    """
    indices = _md_to_indices(md)

    sig_fors = bytearray()
    for i in range(_K):
        idx = indices[i]
        # Secret value at global leaf index i*2^a + idx
        sig_fors += _fors_keygen(sk_seed, pk_seed, adrs, (i << _A) + idx)
        # Authentication path: sibling at each level j
        for j in range(_A):
            s = (idx >> j) ^ 1                       # floor(idx/2^j) xor 1
            auth_idx = (i << (_A - j)) + s           # i*2^(a-j) + s
            sig_fors += _fors_tree_node(sk_seed, pk_seed, adrs, auth_idx, j)
    return bytes(sig_fors)


def _fors_pk_from_sig(sig_fors, md, pk_seed, adrs):
    """Recover FORS public key from signature (Algorithm 17, FIPS 205).

    Expects adrs already has type=FORS_TREE and keypair address set.
    """
    indices = _md_to_indices(md)
    roots = bytearray()

    off = 0
    for i in range(_K):
        idx = indices[i]

        sk = sig_fors[off:off + _N]
        off += _N

        # Global leaf index in the forest
        tree_index = (i << _A) + idx

        # Leaf node
        node_adrs = _adrs_copy(adrs)
        _adrs_set_tree_height(node_adrs, 0)
        _adrs_set_tree_index(node_adrs, tree_index)
        node = _F(pk_seed, node_adrs, sk)

        # Walk up the tree (Algorithm 17 step-by-step parent indexing)
        for j in range(_A):
            auth_j = sig_fors[off:off + _N]
            off += _N

            parent_adrs = _adrs_copy(adrs)
            _adrs_set_tree_height(parent_adrs, j + 1)

            if ((idx >> j) & 1) == 0:
                tree_index >>= 1
                _adrs_set_tree_index(parent_adrs, tree_index)
                node = _H(pk_seed, parent_adrs, node + auth_j)
            else:
                tree_index = (tree_index - 1) >> 1
                _adrs_set_tree_index(parent_adrs, tree_index)
                node = _H(pk_seed, parent_adrs, auth_j + node)

        roots += node

    # Compress the k roots into FORS public key
    fors_pk_adrs = _adrs_copy(adrs)
    _adrs_set_type(fors_pk_adrs, _ADRS_TYPE_FORS_ROOTS)
    _adrs_set_keypair(fors_pk_adrs, struct.unpack_from(">I", adrs, _ADRS_WORD1)[0])
    return _T_l(pk_seed, fors_pk_adrs, bytes(roots))


def _md_to_indices(md):
    """Split message digest into k indices of a bits each."""
    indices = []
    bits = int.from_bytes(md[:_MD_BYTES], "big")
    total_bits = _MD_BYTES * 8
    for i in range(_K):
        shift = total_bits - (i + 1) * _A
        if shift >= 0:
            idx = (bits >> shift) & ((1 << _A) - 1)
        else:
            idx = (bits << (-shift)) & ((1 << _A) - 1)
        indices.append(idx)
    return indices


# ── Top-Level API ──────────────────────────────────────────────────

def slh_keygen(seed):
    """SLH-DSA-SHAKE-128s key generation (Algorithm 21, FIPS 205).

    Args:
        seed: 48-byte seed = SK.seed(16) || SK.prf(16) || PK.seed(16).

    Returns:
        (sk_bytes, pk_bytes) tuple.
        sk_bytes: 64-byte secret key (SK.seed || SK.prf || PK.seed || PK.root).
        pk_bytes: 32-byte public key (PK.seed || PK.root).
    """
    if len(seed) != 3 * _N:
        raise ValueError(f"seed must be {3 * _N} bytes, got {len(seed)}")

    sk_seed = seed[:_N]      # 16 bytes
    sk_prf = seed[_N:2*_N]   # 16 bytes
    pk_seed = seed[2*_N:3*_N]  # 16 bytes

    # Compute root of the top XMSS tree
    adrs = _adrs_new()
    _adrs_set_layer(adrs, _D - 1)
    _adrs_set_tree(adrs, 0)
    pk_root = _xmss_node(sk_seed, pk_seed, 0, _HP, adrs)

    sk_bytes = sk_seed + sk_prf + pk_seed + pk_root
    pk_bytes = pk_seed + pk_root
    return sk_bytes, pk_bytes


def _slh_sign_internal(message, sk_bytes, addrnd=None, deterministic=False):
    """SLH-DSA-SHAKE-128s internal signing (Algorithm 23, FIPS 205).

    Signs pre-processed message M' directly. Use slh_sign() for the
    pure FIPS 205 API with context string support.

    addrnd: Explicit n-byte randomness. If provided, overrides both modes.
    deterministic: If True and addrnd is None, uses PK.seed (deterministic).
                   If False and addrnd is None, generates os.urandom(n) (hedged).
    """
    if len(sk_bytes) != _SK_SIZE:
        raise ValueError(f"secret key must be {_SK_SIZE} bytes, got {len(sk_bytes)}")
    if addrnd is not None:
        addrnd = bytes(addrnd)
        if len(addrnd) != _N:
            raise ValueError(f"addrnd must be {_N} bytes, got {len(addrnd)}")

    sk_seed = sk_bytes[:_N]
    sk_prf = sk_bytes[_N:2*_N]
    pk_seed = sk_bytes[2*_N:3*_N]
    pk_root = sk_bytes[3*_N:4*_N]

    # Step 1: Randomizer R (deterministic or hedged, FIPS 205 Section 10.2.1)
    if addrnd is not None:
        opt_rand = addrnd
    elif deterministic:
        opt_rand = pk_seed
    else:
        opt_rand = os.urandom(_N)
    R = _PRF_msg(sk_prf, opt_rand, message)

    # Step 2: Hash message to get digest
    digest = _H_msg(R, pk_seed, pk_root, message)

    # Step 3: Split digest into (md, idx_tree, idx_leaf)
    md = digest[:_MD_BYTES]
    idx_tree_bytes = digest[_MD_BYTES:_MD_BYTES + _IDX_TREE_BYTES]
    idx_leaf_bytes = digest[_MD_BYTES + _IDX_TREE_BYTES:]

    idx_tree = int.from_bytes(idx_tree_bytes, "big")
    # Mask to valid tree range: h - h/d bits
    idx_tree &= (1 << (_FULL_H - _HP)) - 1
    idx_leaf = int.from_bytes(idx_leaf_bytes, "big")
    idx_leaf &= (1 << _HP) - 1

    # Step 4: FORS signature
    fors_adrs = _adrs_new()
    _adrs_set_layer(fors_adrs, 0)
    _adrs_set_tree(fors_adrs, idx_tree)
    _adrs_set_type(fors_adrs, _ADRS_TYPE_FORS_TREE)
    _adrs_set_keypair(fors_adrs, idx_leaf)
    sig_fors = _fors_sign(md, sk_seed, pk_seed, fors_adrs)

    # Step 5: FORS public key (input to hypertree)
    pk_fors = _fors_pk_from_sig(sig_fors, md, pk_seed, fors_adrs)

    # Step 6: Hypertree signature
    sig_ht = _ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf)

    # Assemble signature: R || SIG_FORS || SIG_HT
    return R + sig_fors + sig_ht


def _slh_verify_internal(message, sig_bytes, pk_bytes):
    """SLH-DSA-SHAKE-128s internal verification (Algorithm 25, FIPS 205).

    Verifies pre-processed message M' directly. Use slh_verify() for the
    pure FIPS 205 API with context string support.
    """
    if len(pk_bytes) != _PK_SIZE:
        return False
    if len(sig_bytes) != _SIG_SIZE:
        return False

    pk_seed = pk_bytes[:_N]
    pk_root = pk_bytes[_N:2*_N]

    # Parse signature
    offset = 0
    R = sig_bytes[offset:offset + _N]
    offset += _N
    fors_sig_size = _K * (1 + _A) * _N
    sig_fors = sig_bytes[offset:offset + fors_sig_size]
    offset += fors_sig_size
    sig_ht = sig_bytes[offset:]

    # Recompute message digest
    digest = _H_msg(R, pk_seed, pk_root, message)
    md = digest[:_MD_BYTES]
    idx_tree_bytes = digest[_MD_BYTES:_MD_BYTES + _IDX_TREE_BYTES]
    idx_leaf_bytes = digest[_MD_BYTES + _IDX_TREE_BYTES:]

    idx_tree = int.from_bytes(idx_tree_bytes, "big")
    idx_tree &= (1 << (_FULL_H - _HP)) - 1
    idx_leaf = int.from_bytes(idx_leaf_bytes, "big")
    idx_leaf &= (1 << _HP) - 1

    # Recover FORS public key
    fors_adrs = _adrs_new()
    _adrs_set_layer(fors_adrs, 0)
    _adrs_set_tree(fors_adrs, idx_tree)
    _adrs_set_type(fors_adrs, _ADRS_TYPE_FORS_TREE)
    _adrs_set_keypair(fors_adrs, idx_leaf)
    pk_fors = _fors_pk_from_sig(sig_fors, md, pk_seed, fors_adrs)

    # Verify hypertree signature
    return _ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root)


def slh_sign(message, sk_bytes, ctx=b"", *, deterministic=False, addrnd=None):
    """SLH-DSA-SHAKE-128s pure signing (Algorithm 22, FIPS 205).

    Builds M' = 0x00 || len(ctx) || ctx || message, then calls the
    internal signing algorithm. This is the FIPS 205 "pure" mode.

    Defaults to hedged signing (FIPS 205 recommended). Pass
    deterministic=True for reproducible signatures.

    Args:
        message: Arbitrary-length message bytes.
        sk_bytes: 64-byte secret key from slh_keygen.
        ctx: Optional context string (0-255 bytes, default empty).
        deterministic: If True, use PK.seed as opt_rand (no randomness).
        addrnd: Explicit n-byte randomness (overrides deterministic flag).

    Returns:
        Signature bytes (7,856 bytes).

    Raises:
        ValueError: If ctx exceeds 255 bytes.
    """
    if len(ctx) > 255:
        raise ValueError(f"context string must be <= 255 bytes, got {len(ctx)}")
    m_prime = b"\x00" + bytes([len(ctx)]) + ctx + message
    return _slh_sign_internal(m_prime, sk_bytes, addrnd=addrnd, deterministic=deterministic)


def slh_verify(message, sig_bytes, pk_bytes, ctx=b""):
    """SLH-DSA-SHAKE-128s pure verification (Algorithm 24, FIPS 205).

    Builds M' = 0x00 || len(ctx) || ctx || message, then calls the
    internal verification algorithm. This is the FIPS 205 "pure" mode.

    Args:
        message: Original message bytes.
        sig_bytes: Signature from slh_sign.
        pk_bytes: 32-byte public key from slh_keygen.
        ctx: Optional context string (must match what was used for signing).

    Returns:
        True if valid, False otherwise.
    """
    if len(ctx) > 255:
        return False
    m_prime = b"\x00" + bytes([len(ctx)]) + ctx + message
    return _slh_verify_internal(m_prime, sig_bytes, pk_bytes)
