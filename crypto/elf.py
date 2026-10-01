"""MiniELF 解析与密钥候选提取。"""
from __future__ import annotations
import struct
from typing import Dict, List, Optional, Tuple

from config import BURDEN_XOR_KEY, MAGIC_BYTES, MAGIC_STRING

def uniq_bytes_list(items: List[bytes]) -> List[bytes]:
    seen = set()
    out = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def split_zero_and_lengths(blob: bytes) -> List[bytes]:
    out = []
    if b"\x00" in blob:
        for part in blob.split(b"\x00"):
            if 16 <= len(part) <= 96:
                out.append(part)
    elif 16 <= len(blob) <= 96:
        out.append(blob)
    for size in (20, 16, 32, 38, 39, 40, 48, 64, 72, 83, 84, 85, 96):
        if len(blob) >= size:
            out.append(blob[:size])
    return uniq_bytes_list(out)


def _looks_like_binary_key_blob(blob: bytes) -> bool:
    if not (16 <= len(blob) <= 96):
        return False
    if not any(blob):
        return False
    printable = sum(1 for b in blob if 0x20 <= b < 0x7F)
    high = sum(1 for b in blob if b >= 0x80)
    distinct = len(set(blob))
    return high >= 4 and printable / max(1, len(blob)) < 0.72 and distinct >= min(12, max(8, len(blob) // 2))


def _key_candidate_rank(blob: bytes) -> Tuple[int, int, int]:
    preferred = {
        20: 0,
        16: 1,
        32: 2,
        38: 3,
        39: 4,
        40: 5,
        48: 6,
        64: 7,
    }
    zeros = sum(1 for b in blob if b == 0)
    return (preferred.get(len(blob), 99), zeros, -len(set(blob)))


class MiniELF:
    def __init__(self, data: bytes):
        self.data = data
        if data[:4] != b"\x7fELF":
            raise ValueError("not ELF")
        self.bits = 64 if data[4] == 2 else 32
        if data[5] != 1:
            raise ValueError("only little endian ELF is supported")
        self._parse64() if self.bits == 64 else self._parse32()
        self._load_section_names()
        self._symbols_cache: Optional[List[Dict[str, int]]] = None

    def _parse64(self) -> None:
        hdr = struct.unpack_from("<16sHHIQQQIHHHHHH", self.data, 0)
        (
            _e_ident,
            self.e_type,
            self.e_machine,
            _e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            _e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        ) = hdr
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            sh = struct.unpack_from("<IIQQQQIIQQ", self.data, off)
            self.sections.append(
                {
                    "name_off": sh[0],
                    "type": sh[1],
                    "flags": sh[2],
                    "addr": sh[3],
                    "offset": sh[4],
                    "size": sh[5],
                    "link": sh[6],
                    "info": sh[7],
                    "addralign": sh[8],
                    "entsize": sh[9],
                }
            )
        self.phdrs = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p = struct.unpack_from("<IIQQQQQQ", self.data, off)
            self.phdrs.append(
                {
                    "type": p[0],
                    "flags": p[1],
                    "offset": p[2],
                    "vaddr": p[3],
                    "paddr": p[4],
                    "filesz": p[5],
                    "memsz": p[6],
                    "align": p[7],
                }
            )

    def _parse32(self) -> None:
        hdr = struct.unpack_from("<16sHHIIIIIHHHHHH", self.data, 0)
        (
            _e_ident,
            self.e_type,
            self.e_machine,
            _e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            _e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        ) = hdr
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            sh = struct.unpack_from("<IIIIIIIIII", self.data, off)
            self.sections.append(
                {
                    "name_off": sh[0],
                    "type": sh[1],
                    "flags": sh[2],
                    "addr": sh[3],
                    "offset": sh[4],
                    "size": sh[5],
                    "link": sh[6],
                    "info": sh[7],
                    "addralign": sh[8],
                    "entsize": sh[9],
                }
            )
        self.phdrs = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p = struct.unpack_from("<IIIIIIII", self.data, off)
            self.phdrs.append(
                {
                    "type": p[0],
                    "offset": p[1],
                    "vaddr": p[2],
                    "paddr": p[3],
                    "filesz": p[4],
                    "memsz": p[5],
                    "flags": p[6],
                    "align": p[7],
                }
            )

    def _load_section_names(self) -> None:
        if not (0 <= self.e_shstrndx < len(self.sections)):
            return
        shstr = self.sections[self.e_shstrndx]
        blob = self.data[shstr["offset"]:shstr["offset"] + shstr["size"]]
        for section in self.sections:
            no = section["name_off"]
            end = blob.find(b"\x00", no)
            section["name"] = blob[no:end].decode("utf-8", "replace") if end >= 0 else ""

    def section_by_name(self, name: str):
        for section in self.sections:
            if section.get("name") == name:
                return section
        return None

    def vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        for phdr in self.phdrs:
            if phdr["type"] != 1:
                continue
            start = phdr["vaddr"]
            end = start + phdr["filesz"]
            if start <= vaddr < end:
                return phdr["offset"] + (vaddr - start)
        for section in self.sections:
            start = section["addr"]
            end = start + section["size"]
            if start <= vaddr < end:
                return section["offset"] + (vaddr - start)
        return None

    def read_symbols(self) -> List[Dict[str, int]]:
        if self._symbols_cache is not None:
            return self._symbols_cache
        out: List[Dict[str, int]] = []
        for sec_name in (".symtab", ".dynsym"):
            sec = self.section_by_name(sec_name)
            if not sec or not sec["entsize"] or sec["link"] >= len(self.sections):
                continue
            strsec = self.sections[sec["link"]]
            strtab = self.data[strsec["offset"]:strsec["offset"] + strsec["size"]]
            for i in range(sec["size"] // sec["entsize"]):
                off = sec["offset"] + i * sec["entsize"]
                if self.bits == 64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", self.data, off)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from("<IIIBBH", self.data, off)
                if st_name >= len(strtab):
                    continue
                end = strtab.find(b"\x00", st_name)
                if end < 0:
                    continue
                name = strtab[st_name:end].decode("utf-8", "replace")
                if name:
                    out.append(
                        {
                            "name": name,
                            "value": st_value,
                            "size": st_size,
                            "info": st_info,
                            "shndx": st_shndx,
                        }
                    )
        self._symbols_cache = out
        return out

    def get_symbols_contains(self, needle: str, fallback_size: int = 0x8000):
        out = []
        for sym in self.read_symbols():
            if needle not in sym["name"]:
                continue
            off = self.vaddr_to_offset(sym["value"])
            if off is None:
                continue
            size = sym["size"] or fallback_size
            out.append((sym, self.data[off:off + size]))
        out.sort(key=lambda item: (0 if item[0]["size"] else 1, item[0]["value"]))
        return out


def arm64_mov_imm_w(insn: int):
    if (insn & 0x7F800000) == 0x52800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        hw = (insn >> 21) & 3
        val = (imm16 << (16 * hw)) & 0xFFFFFFFF
        return rd, val & 0xFF
    if (insn & 0x7F800000) == 0x12800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        hw = (insn >> 21) & 3
        val = (~(imm16 << (16 * hw))) & 0xFFFFFFFF
        return rd, val & 0xFF
    return None


def arm64_strb_unsigned(insn: int):
    if (insn & 0xFFC00000) != 0x39000000:
        return None
    rt = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    imm = (insn >> 10) & 0xFFF
    return rt, rn, imm


def extract_arm64_strb_tables(func_code: bytes, min_len: int = 16) -> List[bytes]:
    regs: Dict[int, int] = {}
    stores = []
    for idx in range(0, len(func_code) - 3, 4):
        insn = struct.unpack_from("<I", func_code, idx)[0]
        mv = arm64_mov_imm_w(insn)
        if mv:
            regs[mv[0]] = mv[1]
            continue
        st = arm64_strb_unsigned(insn)
        if st:
            rt, rn, imm = st
            if rt == 31:
                val = 0
            elif rt in regs:
                val = regs[rt]
            else:
                continue
            stores.append((idx // 4, rn, imm, val & 0xFF))
    candidates: List[bytes] = []
    for start in range(len(stores)):
        base_i, base_r, _off, _val = stores[start]
        local = []
        for insn_i, rn, off, val in stores[start:]:
            if insn_i - base_i > 420:
                break
            if rn == base_r:
                local.append((off, val))
        if len(local) < min_len:
            continue
        values: Dict[int, int] = {}
        for off, val in local:
            values[off] = val
        run = []
        last = None
        for off in sorted(values):
            if last is None or off == last + 1:
                run.append(off)
            else:
                if len(run) >= min_len:
                    candidates.extend(split_zero_and_lengths(bytes(values[x] for x in run)))
                run = [off]
            last = off
        if len(run) >= min_len:
            candidates.extend(split_zero_and_lengths(bytes(values[x] for x in run)))
    return uniq_bytes_list(candidates)


def extract_x86_mov_tables(func_code: bytes, min_len: int = 16) -> List[bytes]:
    stores = []
    i = 0
    n = len(func_code)
    while i < n - 10:
        b0 = func_code[i]
        b1 = func_code[i + 1]
        if b0 == 0xC6 and b1 == 0x45 and i + 4 <= n:
            disp = struct.unpack_from("b", func_code, i + 2)[0]
            imm = func_code[i + 3]
            stores.append((i, "ebp", disp, imm))
            i += 4
            continue
        if b0 == 0xC6 and b1 == 0x85 and i + 7 <= n:
            disp = struct.unpack_from("<i", func_code, i + 2)[0]
            imm = func_code[i + 6]
            stores.append((i, "ebp", disp, imm))
            i += 7
            continue
        if b0 == 0xC7 and b1 == 0x45 and i + 7 <= n:
            disp = struct.unpack_from("b", func_code, i + 2)[0]
            imm32 = func_code[i + 3:i + 7]
            for k, val in enumerate(imm32):
                stores.append((i, "ebp", disp + k, val))
            i += 7
            continue
        if b0 == 0xC7 and b1 == 0x85 and i + 10 <= n:
            disp = struct.unpack_from("<i", func_code, i + 2)[0]
            imm32 = func_code[i + 6:i + 10]
            for k, val in enumerate(imm32):
                stores.append((i, "ebp", disp + k, val))
            i += 10
            continue
        if b0 == 0xC6 and b1 == 0x00 and i + 3 <= n:
            stores.append((i, "eax", 0, func_code[i + 2]))
            i += 3
            continue
        if b0 == 0xC7 and b1 == 0x00 and i + 6 <= n:
            imm32 = func_code[i + 2:i + 6]
            for k, val in enumerate(imm32):
                stores.append((i, "eax", k, val))
            i += 6
            continue
        if b0 == 0xC6 and b1 == 0x40 and i + 4 <= n:
            disp = struct.unpack_from("b", func_code, i + 2)[0]
            stores.append((i, "eax", disp, func_code[i + 3]))
            i += 4
            continue
        if b0 == 0xC6 and b1 == 0x80 and i + 7 <= n:
            disp = struct.unpack_from("<i", func_code, i + 2)[0]
            stores.append((i, "eax", disp, func_code[i + 6]))
            i += 7
            continue
        if b0 == 0xC7 and b1 == 0x40 and i + 7 <= n:
            disp = struct.unpack_from("b", func_code, i + 2)[0]
            imm32 = func_code[i + 3:i + 7]
            for k, val in enumerate(imm32):
                stores.append((i, "eax", disp + k, val))
            i += 7
            continue
        if b0 == 0xC7 and b1 == 0x80 and i + 10 <= n:
            disp = struct.unpack_from("<i", func_code, i + 2)[0]
            imm32 = func_code[i + 6:i + 10]
            for k, val in enumerate(imm32):
                stores.append((i, "eax", disp + k, val))
            i += 10
            continue
        i += 1

    candidates: List[bytes] = []
    for start_idx in range(len(stores)):
        base_i, base_name, _disp, _val = stores[start_idx]
        local = []
        for insn_i, name, disp, val in stores[start_idx:]:
            if insn_i - base_i > 0x700:
                break
            if name == base_name:
                local.append((disp, val))
        if len(local) < min_len:
            continue
        values = {}
        for disp, val in local:
            values[disp] = val & 0xFF
        run = []
        last = None
        for off in sorted(values):
            if last is None or off == last + 1:
                run.append(off)
            else:
                if len(run) >= min_len:
                    candidates.extend(split_zero_and_lengths(bytes(values[x] for x in run)))
                run = [off]
            last = off
        if len(run) >= min_len:
            candidates.extend(split_zero_and_lengths(bytes(values[x] for x in run)))
    return uniq_bytes_list(candidates)


def get_exec_sections(elf: MiniELF):
    out = []
    for section in elf.sections:
        name = section.get("name", "")
        flags = section.get("flags", 0)
        if name == ".text" or (flags & 0x4):
            off = section["offset"]
            size = section["size"]
            out.append((name, section["addr"], elf.data[off:off + size]))
    return out


def get_data_sections(elf: MiniELF):
    out = []
    interesting = {".rodata", ".data", ".data.rel.ro", ".rdata"}
    for section in elf.sections:
        name = section.get("name", "")
        if name not in interesting:
            continue
        off = section["offset"]
        size = section["size"]
        if size <= 0:
            continue
        out.append((name, elf.data[off:off + size]))
    return out


def extract_x86_pic_rodata_copies(elf: MiniELF, func_sym: Dict[str, int], max_len: int = 96) -> List[bytes]:
    base = func_sym["value"]
    off = elf.vaddr_to_offset(base)
    if off is None:
        return []
    size = func_sym.get("size") or 0x8000
    code = elf.data[off:off + size]

    ebx_base = None
    scan_end = min(len(code) - 11, 96)
    for i in range(max(0, scan_end)):
        if code[i] == 0xE8 and code[i + 5:i + 7] == b"\x81\xc3":
            add_imm = struct.unpack_from("<i", code, i + 7)[0]
            ebx_base = (base + i + 5 + add_imm) & 0xFFFFFFFF
            break
    if ebx_base is None:
        return []

    out: List[bytes] = []
    i = 0
    while i < len(code) - 6:
        if code[i] == 0x8D and (code[i + 1] & 0xC7) == 0x83:
            disp = struct.unpack_from("<i", code, i + 2)[0]
            vaddr = (ebx_base + disp) & 0xFFFFFFFF
            roff = elf.vaddr_to_offset(vaddr)
            if roff is not None and 0 <= roff < len(elf.data):
                raw = elf.data[roff:roff + max_len + 1]
                nul = raw.find(b"\x00")
                raw = raw[:nul] if nul >= 0 else raw[:max_len]
                for cand in split_zero_and_lengths(raw):
                    if _looks_like_binary_key_blob(cand):
                        out.append(cand)
            i += 6
            continue
        i += 1
    return uniq_bytes_list(out)


def _x86_find_pic_base_from_code(func_base: int, code: bytes) -> Optional[int]:
    for i in range(0, min(len(code) - 12, 0x120)):
        if code[i] != 0xE8 or i + 12 > len(code):
            continue
        rel = struct.unpack_from("<i", code, i + 1)[0]
        target = (func_base + i + 5 + rel) & 0xFFFFFFFF
        if target != (func_base + i + 5) & 0xFFFFFFFF:
            continue
        pop = code[i + 5]
        if not (0x58 <= pop <= 0x5F):
            continue
        reg = pop - 0x58
        if code[i + 6] == 0x81 and i + 12 <= len(code):
            modrm = code[i + 7]
            if (modrm & 0xF8) == 0xC0 and (modrm & 7) == reg:
                imm = struct.unpack_from("<i", code, i + 8)[0]
                return (func_base + i + 5 + imm) & 0xFFFFFFFF
    return None


def _x86_modrm_disp32_mem(code: bytes, off: int):
    if off >= len(code):
        return None
    modrm = code[off]
    mod = (modrm >> 6) & 3
    reg = (modrm >> 3) & 7
    rm = modrm & 7
    if mod != 2:
        return None
    p = off + 1
    if rm == 4:
        return None
    if p + 4 > len(code):
        return None
    disp = struct.unpack_from("<i", code, p)[0]
    return reg, rm, disp, 5


def extract_x86_sse_rodata_tables(elf: MiniELF, func_sym: Dict[str, int], min_len: int = 16, max_len: int = 128) -> List[bytes]:
    func_base = int(func_sym.get("value") or 0)
    off = elf.vaddr_to_offset(func_base)
    if off is None:
        return []
    code = elf.data[off:off + (func_sym.get("size") or 0x9000)]
    pic_base = _x86_find_pic_base_from_code(func_base, code)
    if pic_base is None:
        return []

    pending = None
    stores = []
    i = 0
    while i < len(code) - 8:
        size = None
        modrm_off = None
        if code[i:i + 2] in (b"\x0f\x28", b"\x0f\x10"):
            size = 16
            modrm_off = i + 2
        elif code[i:i + 3] in (b"\xf3\x0f\x6f", b"\x66\x0f\x6f"):
            size = 16
            modrm_off = i + 3
        elif code[i:i + 3] in (b"\xf2\x0f\x10", b"\xf3\x0f\x7e"):
            size = 8
            modrm_off = i + 3
        if size is not None:
            mem = _x86_modrm_disp32_mem(code, modrm_off)
            if mem is not None:
                _xmm_reg, _base_reg, disp, used = mem
                roff = elf.vaddr_to_offset((pic_base + disp) & 0xFFFFFFFF)
                if roff is not None and 0 <= roff + size <= len(elf.data):
                    pending = (i, elf.data[roff:roff + size], size)
                    i = modrm_off + used
                    continue

        if pending is not None:
            data = pending[1]
            if len(data) == 16 and code[i:i + 3] in (b"\x0f\x11\x00", b"\x0f\x29\x00"):
                stores.append((i, "eax", 0, data))
                pending = None
                i += 3
                continue
            if len(data) == 16 and code[i:i + 3] == b"\x0f\x11\x40" and i + 4 <= len(code):
                stores.append((i, "eax", struct.unpack_from("b", code, i + 3)[0], data))
                pending = None
                i += 4
                continue
            if len(data) == 16 and code[i:i + 4] in (b"\x0f\x29\x44\x24", b"\x0f\x11\x44\x24") and i + 5 <= len(code):
                stores.append((i, "esp", code[i + 4], data))
                pending = None
                i += 5
                continue
            if len(data) == 16 and code[i:i + 5] == b"\x66\x0f\x7f\x44\x24" and i + 6 <= len(code):
                stores.append((i, "esp", code[i + 5], data))
                pending = None
                i += 6
                continue
            if len(data) == 8 and code[i:i + 3] == b"\xf2\x0f\x11" and i + 5 <= len(code):
                modrm = code[i + 3]
                if modrm == 0x00:
                    stores.append((i, "eax", 0, data))
                    pending = None
                    i += 4
                    continue
                if modrm == 0x40:
                    stores.append((i, "eax", struct.unpack_from("b", code, i + 4)[0], data))
                    pending = None
                    i += 5
                    continue
                if modrm == 0x44 and i + 6 <= len(code) and code[i + 4] == 0x24:
                    stores.append((i, "esp", code[i + 5], data))
                    pending = None
                    i += 6
                    continue
        i += 1

    out: List[bytes] = []
    for start in range(len(stores)):
        base_i, base_name, _disp, _data = stores[start]
        values: Dict[int, int] = {}
        for insn_i, name, disp, data in stores[start:]:
            if insn_i - base_i > 0x90:
                break
            if name != base_name:
                continue
            for k, b in enumerate(data):
                values[disp + k] = b
        if len(values) < min_len:
            continue
        run = []
        last = None
        for off2 in sorted(values):
            if last is None or off2 == last + 1:
                run.append(off2)
            else:
                if len(run) >= min_len:
                    blob = bytes(values[x] for x in run[:max_len])
                    out.extend(split_zero_and_lengths(blob))
                run = [off2]
            last = off2
        if len(run) >= min_len:
            blob = bytes(values[x] for x in run[:max_len])
            out.extend(split_zero_and_lengths(blob))
    return uniq_bytes_list([x for x in out if 16 <= len(x) <= max_len and _looks_like_binary_key_blob(x)])


def arm64_rodata_refs(elf: "MiniELF", code: bytes, base: int) -> List[Tuple[int, bool]]:
    """AArch64: scan for ``adrp`` + ``add``/``ldr`` pairs that resolve into .rodata.

    Returns ``(vaddr, is_16byte_vector_load)`` tuples in instruction order.
    """
    refs: List[Tuple[int, bool]] = []
    n = len(code)
    for i in range(0, n - 3, 4):
        insn = struct.unpack_from("<I", code, i)[0]
        if (insn & 0x9F000000) != 0x90000000:
            continue
        rd = insn & 0x1F
        imm21 = ((insn >> 5) & 0x7FFFF) << 2 | (insn >> 29) & 0x3
        if imm21 & 0x100000:
            imm21 -= 0x200000
        page = ((base + i) & ~0xFFF) + (imm21 << 12)
        for j in range(i + 4, min(i + 24, n - 3), 4):
            insn2 = struct.unpack_from("<I", code, j)[0]
            rn = (insn2 >> 5) & 0x1F
            opc = insn2 & 0xFFC00000
            if opc == 0x91000000 and rn == rd:  # add x, x, #imm12
                refs.append((page + ((insn2 >> 10) & 0xFFF), False))
                break
            if opc == 0xF9400000 and rn == rd:  # ldr x, [x, #imm*8]
                refs.append((page + (((insn2 >> 10) & 0xFFF) * 8), False))
                break
            if opc == 0xB9400000 and rn == rd:  # ldr w, [x, #imm*4]
                refs.append((page + (((insn2 >> 10) & 0xFFF) * 4), False))
                break
            if opc == 0x3DC00000 and rn == rd:  # ldr q, [x, #imm*16]
                refs.append((page + (((insn2 >> 10) & 0xFFF) * 16), True))
                break
    return refs


def x86_64_rodata_refs(elf: "MiniELF", code: bytes, base: int) -> List[Tuple[int, bool]]:
    """x86-64: scan for RIP-relative ``lea``/``mov``/``movdqa`` loads into .rodata."""
    refs: List[Tuple[int, bool]] = []
    n = len(code)
    i = 0
    while i < n:
        kind = None
        modrm_off = None
        if code[i:i + 2] == b"\x48\x8d":
            kind = "addr"; modrm_off = i + 2
        elif code[i:i + 2] == b"\x48\x8b":
            kind = "addr"; modrm_off = i + 2
        elif code[i:i + 3] == b"\x66\x0f\x6f":
            kind = "q16"; modrm_off = i + 3
        elif code[i:i + 3] == b"\xf3\x0f\x6f":
            kind = "q16"; modrm_off = i + 3
        elif code[i:i + 2] == b"\x0f\x28":
            kind = "q16"; modrm_off = i + 2
        elif code[i:i + 2] == b"\x0f\x10":
            kind = "q16"; modrm_off = i + 2
        if kind is not None and modrm_off is not None and modrm_off + 4 < n:
            modrm = code[modrm_off]
            if (modrm & 0xC7) == 0x05:  # mod=00 rm=101 => rip+disp32
                disp = struct.unpack_from("<i", code, modrm_off + 1)[0]
                target = (base + modrm_off + 5 + disp) & 0xFFFFFFFFFFFFFFFF
                refs.append((target, kind == "q16"))
                i = modrm_off + 5
                continue
        i += 1
    return refs


def arm32_rodata_refs(elf: "MiniELF", code: bytes, base: int) -> List[Tuple[int, bool]]:
    """ARM (Thumb-2): resolve ``ldr [pc,#imm]``+``add rN,pc`` and ``addw rN,pc,#imm``."""
    refs: List[Tuple[int, bool]] = []
    n = len(code)
    i = 0
    while i < n - 1:
        h = struct.unpack_from("<H", code, i)[0]
        # Thumb-2 addw rN, pc, #imm12 (16-byte NEON loads follow)
        if (h == 0xF20F or h == 0xF30F) and i + 3 < n:
            hw1 = struct.unpack_from("<H", code, i + 2)[0]
            imm12 = (((h >> 10) & 1) << 11) | (((hw1 >> 12) & 0xF) << 8) | (hw1 & 0xFF)
            vaddr = (((base + i + 4) & ~3) + imm12) & 0xFFFFFFFF
            refs.append((vaddr, True))
            i += 4
            continue
        # Thumb ldr rN, [pc, #imm] followed by add rN, pc
        if 0x4800 <= h <= 0x4FFF:
            rn = (h >> 8) & 7
            pool = ((base + i + 4) & ~3) + (h & 0xFF) * 4
            step = 2
        elif h == 0xF8DF and i + 3 < n:
            rn = code[i + 2] & 0xF
            imm12 = ((code[i + 2] >> 4) & 0xF) | (code[i + 3] << 4)
            pool = ((base + i + 4) & ~3) + imm12
            step = 4
        else:
            i += 2
            continue
        poff = elf.vaddr_to_offset(pool)
        if poff is None or poff + 4 > len(elf.data):
            i += 2
            continue
        pval = struct.unpack_from("<I", elf.data, poff)[0]
        found = None
        for k in range(step, min(step + 16, n - 1), 2):
            h2 = struct.unpack_from("<H", code, i + k)[0]
            if (h2 & 0xFF78) == 0x4478 and (h2 & 7) == rn:
                found = i + k
                break
        if found is None:
            i += step
            continue
        vaddr = (pval + (base + found + 4)) & 0xFFFFFFFF
        refs.append((vaddr, False))
        i = found + 2
    return refs


def _collect_func_ref_blobs(
    elf: "MiniELF",
    funcs: List[Tuple[Dict[str, int], bytes]],
    refs_fn,
    want16: bool,
) -> List[bytes]:
    """Read the .rodata/.text blobs referenced by a list of functions."""
    out: List[bytes] = []
    for sym, _code in funcs:
        # ARM (Thumb) symbols carry the Thumb bit in their value; re-read code from
        # the even-aligned base so the byte offset matches the PC arithmetic below.
        base = (sym["value"] & ~1) if elf.e_machine == 40 else sym["value"]
        off = elf.vaddr_to_offset(base)
        if off is None:
            continue
        code = elf.data[off:off + (sym["size"] or 0x8000)]
        for vaddr, _is16 in refs_fn(elf, code, base):
            roff = elf.vaddr_to_offset(vaddr)
            if roff is None:
                continue
            if want16:
                blob = elf.data[roff:roff + 16]
                if _looks_like_binary_key_blob(blob):
                    out.append(blob)
            else:
                raw = elf.data[roff:roff + 96]
                nul = raw.find(b"\x00")
                blob = raw[:nul] if nul >= 0 else raw[:96]
                if _looks_like_binary_key_blob(blob):
                    out.extend(split_zero_and_lengths(blob))
    return out


def extract_key_candidates_from_so(so_data: Optional[bytes]) -> Tuple[List[bytes], List[bytes]]:
    if not so_data:
        return [], []

    post_candidates: List[bytes] = []
    xor_candidates: List[bytes] = []
    fallback_post: List[bytes] = []
    fallback_xor: List[bytes] = []

    if MAGIC_BYTES in so_data:
        fallback_post.append(MAGIC_BYTES)
    if MAGIC_STRING in so_data:
        fallback_post.append(MAGIC_STRING)
    if BURDEN_XOR_KEY in so_data:
        fallback_xor.append(BURDEN_XOR_KEY)

    elf = None
    if so_data[:4] == b"\x7fELF":
        try:
            elf = MiniELF(so_data)
        except Exception:
            elf = None

    if elf is not None:
        slky_funcs = elf.get_symbols_contains("_ZN4iapp4slky", 0x8000)
        burden_funcs = elf.get_symbols_contains("_ZN4iapp6burden1b", 0x9000)

        if elf.e_machine == 3:
            # x86-32: keep the instruction-scan extractors (they were built for it).
            for sym, code in slky_funcs:
                local = []
                local.extend(extract_x86_pic_rodata_copies(elf, sym))
                local.extend(extract_x86_sse_rodata_tables(elf, sym))
                if not local:
                    local.extend(extract_x86_mov_tables(code))
                post_candidates.extend(uniq_bytes_list(local))
            for sym, code in burden_funcs:
                local = []
                local.extend(extract_x86_sse_rodata_tables(elf, sym))
                if not local:
                    local.extend(extract_x86_mov_tables(code))
                xor_candidates.extend(uniq_bytes_list(local))
        elif elf.e_machine in (183, 62, 40):
            # AArch64 / x86-64 / ARM(Thumb-2): follow the functions' .rodata/.text
            # references. The key constants are byte-identical across arches, so
            # this yields the same values as the x86-32 path.
            refs_fn = {183: arm64_rodata_refs, 62: x86_64_rodata_refs, 40: arm32_rodata_refs}[elf.e_machine]
            post_candidates.extend(_collect_func_ref_blobs(elf, slky_funcs, refs_fn, want16=False))
            xor_candidates.extend(_collect_func_ref_blobs(elf, burden_funcs, refs_fn, want16=True))

        if not post_candidates or not xor_candidates:
            for _sec_name, _sec_vaddr, code in get_exec_sections(elf):
                if elf.e_machine == 183:
                    cands = extract_arm64_strb_tables(code)
                elif elf.e_machine in (3, 62):
                    cands = extract_x86_mov_tables(code)
                else:
                    cands = []
                if not post_candidates:
                    fallback_post.extend(cands)
                if not xor_candidates:
                    fallback_xor.extend(cands)

        for _sec_name, blob in get_data_sections(elf):
            for part in blob.split(b"\x00"):
                if not (16 <= len(part) <= 160):
                    continue
                for cand in split_zero_and_lengths(part):
                    if not _looks_like_binary_key_blob(cand):
                        continue
                    fallback_post.append(cand)
                    if len(cand) in (20, 38, 39, 40):
                        fallback_xor.append(cand)

    for part in so_data.split(b"\x00"):
        if not (16 <= len(part) <= 160):
            continue
        for cand in split_zero_and_lengths(part):
            if not _looks_like_binary_key_blob(cand):
                continue
            fallback_post.append(cand)
            if len(cand) in (20, 38, 39, 40):
                fallback_xor.append(cand)

    post_candidates = uniq_bytes_list(post_candidates)
    xor_candidates = uniq_bytes_list(xor_candidates)
    fallback_post = uniq_bytes_list(fallback_post)
    fallback_xor = uniq_bytes_list(fallback_xor)
    # The full post_key (longest contiguous blob) is what matters; chunk-loaded
    # architectures (e.g. x86-64) reference its tail chunks first, so surface the
    # full key by length so generate_key_sets tries it before the 20-candidate cap.
    post_candidates.sort(key=len, reverse=True)
    xor_candidates.sort(key=len, reverse=True)
    fallback_post.sort(key=_key_candidate_rank)
    fallback_xor.sort(key=_key_candidate_rank)
    post_out = uniq_bytes_list(post_candidates + fallback_post)
    xor_out = uniq_bytes_list(xor_candidates + fallback_xor)
    return post_out[:8], xor_out[:8]
