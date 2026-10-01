"""current 算法族的密钥派生候选。"""
from __future__ import annotations
from typing import Dict, List, Optional, Tuple

from config import MAGIC_BYTES, MAGIC_STRING
from crypto.aes import cyclic_xor
from crypto.slky import slky

from algorithms.common import (
    DecryptConfig,
    KeySet,
    OuterCandidate,
    _idbfj_pick6,
    idbfj_seed,
    resolve_post_key_mode,
)

class LegacyOuterCandidate(OuterCandidate):
    def __init__(
        self,
        name: str,
        idbfj_mode: str,
        password_name: Optional[str],
        p19_post_mode: str,
        p24_post_mode: str,
        transform: str,
        confidence: int,
    ):
        super().__init__(name, confidence)
        self.idbfj_mode = idbfj_mode
        self.password_name = password_name
        self.p19_post_mode = p19_post_mode
        self.p24_post_mode = p24_post_mode
        self.transform = transform

    def derive(self, env: Dict[str, bytes], key_set: KeySet) -> Tuple[bytes, Dict[str, bytes]]:
        p19_post_key = resolve_post_key_mode(self.p19_post_mode, key_set)
        p24_post_key = resolve_post_key_mode(self.p24_post_mode, key_set)
        p19, meta = idbfj_seed(env, self.password_name, self.idbfj_mode, p19_post_key)
        p24 = slky(p19, p19, p24_post_key)
        p25 = slky(p19, p24, p24_post_key)
        if self.transform == "xor":
            outer_key = cyclic_xor(p25, key_set.xor_key)[:16]
        elif self.transform == "direct":
            outer_key = p25[:16]
        else:
            raise ValueError(f"unknown transform: {self.transform}")
        trace = {
            "candidate": self.name.encode("utf-8"),
            "key_set": key_set.name.encode("utf-8"),
            "outer_key": outer_key,
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "transform": self.transform.encode("ascii"),
            "p19_post_mode": self.p19_post_mode.encode("ascii"),
            "p24_post_mode": self.p24_post_mode.encode("ascii"),
        }
        trace.update(meta)
        return outer_key, trace


class EnvP25Candidate(OuterCandidate):
    def __init__(
        self,
        first_name: str,
        second_name: str,
        post_mode: str,
        transform: str,
        confidence: int,
    ):
        super().__init__(f"env:{first_name}:{second_name}:{post_mode}:{transform}", confidence)
        self.first_name = first_name
        self.second_name = second_name
        self.post_mode = post_mode
        self.transform = transform

    def derive(self, env: Dict[str, bytes], key_set: KeySet) -> Tuple[bytes, Dict[str, bytes]]:
        first = env[self.first_name]
        second = env[self.second_name]
        post_key = resolve_post_key_mode(self.post_mode, key_set)
        p19 = slky(first, second, post_key)
        p24 = slky(p19, p19, post_key)
        p25 = slky(p19, p24, post_key)
        if self.transform == "xor":
            outer_key = cyclic_xor(p25, key_set.xor_key)[:16]
        elif self.transform == "direct":
            outer_key = p25[:16]
        else:
            raise ValueError(f"unknown transform: {self.transform}")
        return outer_key, {
            "candidate": self.name.encode("utf-8"),
            "key_set": key_set.name.encode("utf-8"),
            "outer_key": outer_key,
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "transform": self.transform.encode("ascii"),
            "post_mode": self.post_mode.encode("ascii"),
        }


class NativeX86IdbfjP25Candidate(OuterCandidate):
    def __init__(self, input_name: str, confidence: int = 98):
        super().__init__(f"native:x86_idbfj_{input_name}:p19_p24_p25:xor", confidence)
        self.input_name = input_name

    def derive(self, env: Dict[str, bytes], key_set: KeySet) -> Tuple[bytes, Dict[str, bytes]]:
        inp = env[self.input_name]
        hidden = env["sok"]
        base = env["base"]
        first = base if inp == hidden else base + inp
        seconds = [
            env["version_name"],
            env["package_name"],
            env["app_name"],
            env["version_code"],
            env["sok"],
            env["dek"],
        ]
        pick = _idbfj_pick6(first)
        if not 0 <= pick < len(seconds):
            raise ValueError(f"idbfj pick out of range: {pick}")
        second = seconds[pick]
        p19 = slky(first, second, key_set.post_key)
        p24 = slky(p19, p19, key_set.post_key)
        p25 = slky(p19, p24, key_set.post_key)
        outer_key = cyclic_xor(p25, key_set.xor_key)[:16]
        return outer_key, {
            "candidate": self.name.encode("utf-8"),
            "key_set": key_set.name.encode("utf-8"),
            "outer_key": outer_key,
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "transform": b"xor",
            "idbfj_input": inp,
            "idbfj_first": first,
            "idbfj_pick": str(pick).encode("ascii"),
            "idbfj_second": second,
            "algorithm": (
                f"native:x86_idbfj_{self.input_name}: outer_key=xor_repeat(p25, KEY_XOR_CONST)[:16] "
                f"where p19=idbfj({self.input_name}), p24=slky(p19,p19), p25=slky(p19,p24)"
            ).encode("utf-8"),
            "post_mode": b"keyset",
        }


class NativeX86IdbfjP25SignatureCandidate(OuterCandidate):
    """Current-algorithm idbfj chain bound to the APK signing certificate.

    Used when signature verification is disabled in extra_conf1g.xml (the
    file is absent or empty): the native lib replaces ``p24 = slky(p19, p19)``
    with ``p24 = slky(signature_der, p19)`` where ``signature_der`` is the raw
    DER bytes of the APK signing certificate (``Signature.toByteArray()``).
    """

    def __init__(self, input_name: str = "sok", confidence: int = 97):
        super().__init__(f"native:x86_idbfj_{input_name}:p19_sig_p25:xor", confidence)
        self.input_name = input_name

    def derive(self, env: Dict[str, bytes], key_set: KeySet) -> Tuple[bytes, Dict[str, bytes]]:
        signature = env.get("signature") or b""
        if not signature:
            raise ValueError("signature (sign_b64) is required for signature-bound candidate")
        inp = env[self.input_name]
        hidden = env["sok"]
        base = env["base"]
        first = base if inp == hidden else base + inp
        seconds = [
            env["version_name"],
            env["package_name"],
            env["app_name"],
            env["version_code"],
            env["sok"],
            env["dek"],
        ]
        pick = _idbfj_pick6(first)
        if not 0 <= pick < len(seconds):
            raise ValueError(f"idbfj pick out of range: {pick}")
        second = seconds[pick]
        p19 = slky(first, second, key_set.post_key)
        p24 = slky(signature, p19, key_set.post_key)
        p25 = slky(p19, p24, key_set.post_key)
        outer_key = cyclic_xor(p25, key_set.xor_key)[:16]
        return outer_key, {
            "candidate": self.name.encode("utf-8"),
            "key_set": key_set.name.encode("utf-8"),
            "outer_key": outer_key,
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "transform": b"xor",
            "idbfj_input": inp,
            "idbfj_first": first,
            "idbfj_pick": str(pick).encode("ascii"),
            "idbfj_second": second,
            "signature": signature,
            "algorithm": (
                f"native:x86_idbfj_{self.input_name}:signature: outer_key=xor_repeat(p25, KEY_XOR_CONST)[:16] "
                f"where p19=idbfj({self.input_name}), p24=slky(signature_der,p19), p25=slky(p19,p24)"
            ).encode("utf-8"),
            "post_mode": b"keyset",
        }
