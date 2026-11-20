#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
SPAKE2 P-256 test vector generator for trill.
Verifies RFC 9382 Appendix B vectors and generates:
  - protocol/testvectors/spake2_rfc9382_p256.json
  - protocol/testvectors/pair_v1.json
"""

import base64
import hashlib
import hmac
import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
CURVE_A = P - 3
CURVE_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = (GX, GY)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = ((3 * x1 * x1 + CURVE_A) * pow(2 * y1, -1, P)) % P
    else:
        lam = ((y2 - y1) * pow(x2 - x1, -1, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, pt):
    res = None
    addend = pt
    k = k % N
    while k > 0:
        if k & 1:
            res = point_add(res, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return res


def decode_pt(s):
    data = bytes.fromhex(s)
    if data[0] == 4 and len(data) == 65:
        return (int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big"))
    if data[0] in (2, 3) and len(data) == 33:
        x = int.from_bytes(data[1:], "big")
        y2 = (pow(x, 3, P) + CURVE_A * x + CURVE_B) % P
        y = pow(y2, (P + 1) // 4, P)
        if (y & 1) != (data[0] & 1):
            y = P - y
        return (x, y)
    raise ValueError(f"Invalid point: {s}")


def encode_pt(pt):
    return bytes([4]) + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


M = decode_pt("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
N_pt = decode_pt("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")


def len_prefixed(b: bytes) -> bytes:
    return len(b).to_bytes(8, "little") + b


def spake2_core(id_a: bytes, id_b: bytes, w: int, x: int, y: int):
    pA = point_add(point_mul(w, M), point_mul(x, G))
    pB = point_add(point_mul(w, N_pt), point_mul(y, G))

    neg_wN = (N_pt[0], P - N_pt[1])
    K_A = point_mul(x, point_add(pB, point_mul(w, neg_wN)))

    neg_wM = (M[0], P - M[1])
    K_B = point_mul(y, point_add(pA, point_mul(w, neg_wM)))
    assert K_A == K_B, "Shared points K do not match"

    pA_bytes = encode_pt(pA)
    pB_bytes = encode_pt(pB)
    K_bytes = encode_pt(K_A)
    w_bytes = w.to_bytes(32, "big")

    tt = (
        len_prefixed(id_a)
        + len_prefixed(id_b)
        + len_prefixed(pA_bytes)
        + len_prefixed(pB_bytes)
        + len_prefixed(K_bytes)
        + len_prefixed(w_bytes)
    )

    hash_tt = hashlib.sha256(tt).digest()
    ke = hash_tt[:16]
    ka = hash_tt[16:]

    kc = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"ConfirmationKeys"
    ).derive(ka)
    kca = kc[:16]
    kcb = kc[16:]

    rfc_cA = hmac.new(kca, tt, hashlib.sha256).digest()
    rfc_cB = hmac.new(kcb, tt, hashlib.sha256).digest()

    # trill binding: A sends MAC(KcA, pB), B sends MAC(KcB, pA)
    ar_cA = hmac.new(kca, pB_bytes, hashlib.sha256).digest()
    ar_cB = hmac.new(kcb, pA_bytes, hashlib.sha256).digest()

    return {
        "pA": pA_bytes,
        "pB": pB_bytes,
        "K": K_bytes,
        "TT": tt,
        "hash_TT": hash_tt,
        "ke": ke,
        "ka": ka,
        "kca": kca,
        "kcb": kcb,
        "rfc_cA": rfc_cA,
        "rfc_cB": rfc_cB,
        "ar_cA": ar_cA,
        "ar_cB": ar_cB,
    }


def verify_rfc_vectors():
    rfc_cases = [
        {
            "id_a": b"server",
            "id_b": b"client",
            "w": 0x2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f,
            "x": 0x43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729,
            "y": 0xdcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be,
            "exp_pA": "04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c",
            "exp_pB": "0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7",
            "exp_K": "0412af7e89717850671913e6b469ace67bd90a4df8ce45c2af19010175e37eed69f75897996d539356e2fa6a406d528501f907e04d97515fbe83db277b715d3325",
            "exp_hash_TT": "0e0672dc86f8e45565d338b0540abe6915bdf72e2b35b5c9e5663168e960a91b",
            "exp_cA": "58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0",
            "exp_cB": "d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b",
        },
        {
            "id_a": b"",
            "id_b": b"client",
            "w": 0x0548d8729f730589e579b0475a582c1608138ddf7054b73b5381c7e883e2efae,
            "x": 0x403abbe3b1b4b9ba17e3032849759d723939a27a27b9d921c500edde18ed654b,
            "y": 0x903023b6598908936ea7c929bd761af6039577a9c3f9581064187c3049d87065,
            "exp_pA": "04a897b769e681c62ac1c2357319a3d363f610839c4477720d24cbe32f5fd85f44fb92ba966578c1b712be6962498834078262caa5b441ecfa9d4a9485720e918a",
            "exp_pB": "04e0f816fd1c35e22065d5556215c097e799390d16661c386e0ecc84593974a61b881a8c82327687d0501862970c64565560cb5671f696048050ca66ca5f8cc7fc",
            "exp_K": "048f83ec9f6e4f87cc6f9dc740bdc2769725f923364f01c84148c049a39a735ebda82eac03e00112fd6a5710682767cff5361f7e819e53d8d3c3a2922e0d837aa6",
            "exp_hash_TT": "642f05c473c2cd79909f9a841e2f30a70bf89b18180af97353ba198789c2b963",
            "exp_cA": "47d29e6666af1b7dd450d571233085d7a9866e4d49d2645e2df975489521232b",
            "exp_cB": "3313c5cefc361d27fb16847a91c2a73b766ffa90a4839122a9b70a2f6bd1d6df",
        },
        {
            "id_a": b"server",
            "id_b": b"",
            "w": 0x626e0cdc7b14c9db3e52a0b1b3a768c98e37852d5db30febe0497b14eae8c254,
            "x": 0x07adb3db6bc623d3399726bfdbfd3d15a58ea776ab8a308b00392621291f9633,
            "y": 0xb6a4fc8dbb629d4ba51d6f91ed1532cf87adec98f25dd153a75accafafedec16,
            "exp_pA": "04f88fb71c99bfffaea370966b7eb99cd4be0ff1a7d335caac4211c4afd855e2e15a873b298503ad8ba1d9cbb9a392d2ba309b48bfd7879aefd0f2cea6009763b0",
            "exp_pB": "040c269d6be017dccb15182ac6bfcd9e2a14de019dd587eaf4bdfd353f031101e7cca177f8eb362a6e83e7d5e729c0732e1b528879c086f39ba0f31a9661bd34db",
            "exp_K": "0445ee233b8ecb51ebd6e7da3f307e88a1616bae2166121221fdc0dadb986afaf3ec8a988dc9c626fa3b99f58a7ca7c9b844bb3e8dd9554aafc5b53813504c1cbe",
            "exp_hash_TT": "005184ff460da2ce59062c87733c299c3521297d736598fc0a1127600efa1afb",
            "exp_cA": "bc9f9bbe99f26d0b2260e6456e05a86196a3307ec6663a18bf6ac825736533b2",
            "exp_cB": "c2370e1bf813b086dff0d834e74425a06e6390f48f5411900276dcccc5a297ec",
        },
        {
            "id_a": b"",
            "id_b": b"",
            "w": 0x7bf46c454b4c1b25799527d896508afd5fc62ef4ec59db1efb49113063d70cca,
            "x": 0x8cef65df64bb2d0f83540c53632de911b5b24b3eab6cc74a97609fd659e95473,
            "y": 0xd7a66f64074a84652d8d623a92e20c9675c61cb5b4f6a0063e4648a2fdc02d53,
            "exp_pA": "04a65b367a3f613cf9f0654b1b28a1e3a8a40387956c8ba6063e8658563890f46ca1ef6a676598889fc28de2950ab8120b79a5ef1ea4c9f44bc98f585634b46d66",
            "exp_pB": "04589f13218822710d98d8b2123a079041052d9941b9cf88c6617ddb2fcc0494662eea8ba6b64692dc318250030c6af045cb738bc81ba35b043c3dcb46adf6f58d",
            "exp_K": "041a3c03d51b452537ca2a1fea6110353c6d5ed483c4f0f86f4492ca3f378d40a994b4477f93c64d928edbbcd3e85a7c709b7ea73ee97986ce3d1438e135543772",
            "exp_hash_TT": "fc6374762ba5cf11f4b2caa08b2cd1b9907ae0e26e8d6234318d91583cd74c86",
            "exp_cA": "dfb4db8d48ae5a675963ea5e6c19d98d4ea028d8e898dad96ea19a80ade95dca",
            "exp_cB": "d0f0609d1613138d354f7e95f19fb556bf52d751947241e8c7118df5ef0ae175",
        },
    ]

    out_cases = []
    for i, c in enumerate(rfc_cases):
        res = spake2_core(c["id_a"], c["id_b"], c["w"], c["x"], c["y"])
        assert res["pA"].hex() == c["exp_pA"]
        assert res["pB"].hex() == c["exp_pB"]
        assert res["K"].hex() == c["exp_K"]
        assert res["hash_TT"].hex() == c["exp_hash_TT"]
        assert res["rfc_cA"].hex() == c["exp_cA"]
        assert res["rfc_cB"].hex() == c["exp_cB"]

        out_cases.append(
            {
                "description": f"RFC 9382 Appendix B case {i + 1}",
                "id_a": c["id_a"].decode("ascii", errors="replace"),
                "id_b": c["id_b"].decode("ascii", errors="replace"),
                "w": f"{c['w']:064x}",
                "x": f"{c['x']:064x}",
                "y": f"{c['y']:064x}",
                "pA": res["pA"].hex(),
                "pB": res["pB"].hex(),
                "K": res["K"].hex(),
                "TT": res["TT"].hex(),
                "hash_TT": res["hash_TT"].hex(),
                "Ke": res["ke"].hex(),
                "Ka": res["ka"].hex(),
                "KcA": res["kca"].hex(),
                "KcB": res["kcb"].hex(),
                "rfc_confirm_a": res["rfc_cA"].hex(),
                "rfc_confirm_b": res["rfc_cB"].hex(),
            }
        )

    print(f"Verified {len(rfc_cases)} RFC 9382 test cases successfully.")
    return out_cases


def derive_w(code_str: str) -> int:
    # w = OS2IP(HKDF-SHA256(ikm=code, salt="trill/spake2/w/v1", info="", L=48)) mod n
    salt = b"trill/spake2/w/v1"
    ikm = code_str.encode("utf-8")
    raw = HKDF(algorithm=hashes.SHA256(), length=48, salt=salt, info=b"").derive(ikm)
    return int.from_bytes(raw, "big") % N


def generate_pair_v1():
    code = "839201"
    phone_spki = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    host_spki = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

    id_a = f"tr-phone:{phone_spki}".encode("ascii")
    id_b = f"tr-host:{host_spki}".encode("ascii")

    w = derive_w(code)
    # Fixed ephemeral scalars for deterministic vectors
    x = 0x43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729
    y = 0xdcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be

    res = spake2_core(id_a, id_b, w, x, y)

    vector = {
        "suite": "P256-SHA256-HKDF-HMAC",
        "code": code,
        "w_hex": f"{w:064x}",
        "phone_spki_hex": phone_spki,
        "host_spki_hex": host_spki,
        "id_a": id_a.decode("ascii"),
        "id_b": id_b.decode("ascii"),
        "scalar_a_hex": f"{x:064x}",
        "scalar_b_hex": f"{y:064x}",
        "share_a_hex": res["pA"].hex(),
        "share_a_b64": base64.b64encode(res["pA"]).decode("ascii"),
        "share_b_hex": res["pB"].hex(),
        "share_b_b64": base64.b64encode(res["pB"]).decode("ascii"),
        "K_hex": res["K"].hex(),
        "TT_hex": res["TT"].hex(),
        "hash_TT_hex": res["hash_TT"].hex(),
        "Ke_hex": res["ke"].hex(),
        "Ka_hex": res["ka"].hex(),
        "KcA_hex": res["kca"].hex(),
        "KcB_hex": res["kcb"].hex(),
        "confirm_a_hex": res["ar_cA"].hex(),
        "confirm_a_b64": base64.b64encode(res["ar_cA"]).decode("ascii"),
        "confirm_b_hex": res["ar_cB"].hex(),
        "confirm_b_b64": base64.b64encode(res["ar_cB"]).decode("ascii"),
    }
    return vector


def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    protocol_dir = os.path.join(repo_root, "protocol")
    tv_dir = os.path.join(protocol_dir, "testvectors")
    os.makedirs(tv_dir, exist_ok=True)

    rfc_cases = verify_rfc_vectors()
    rfc_path = os.path.join(tv_dir, "spake2_rfc9382_p256.json")
    with open(rfc_path, "w", encoding="utf-8") as f:
        json.dump({"cases": rfc_cases}, f, indent=2)
    print(f"Wrote {rfc_path}")

    pair_v1 = generate_pair_v1()
    pair_path = os.path.join(tv_dir, "pair_v1.json")
    with open(pair_path, "w", encoding="utf-8") as f:
        json.dump(pair_v1, f, indent=2)
    print(f"Wrote {pair_path}")


if __name__ == "__main__":
    main()
