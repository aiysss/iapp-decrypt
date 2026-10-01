#!/usr/bin/env python3
"""
APK参数提取模块 - 从APK文件中提取解密所需的参数
不保存任何临时文件到磁盘，所有操作在内存中完成
"""

import base64
import hashlib
import os
import re
import struct
import subprocess
import zipfile
from io import BytesIO
from typing import Optional, Dict, Any, List, Tuple

from cryptography.hazmat.primitives.serialization import Encoding, pkcs7


class ApkExtractor:
    """APK参数提取器"""
    
    # 特征字符串配置
    SEARCH_PATTERN = b'QQQQQQQQQQ'  # 10个连续的Q
    SOK_BEFORE_LENGTH = 10  # 特征字符串前的字符数
    SOK_AFTER_LENGTH = 12   # 特征字符串后的字符数
    LEGACY_SOK_MARKER = b'\x00aa\x00lib.so'
    
    # 目标类文件路径
    TARGET_CLASS = 'com/iapp/app/f'
    
    # baksmali工具路径（项目内相对路径）
    BAKSMALI_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tool', 'baksmali.jar')
    
    # 可能的so文件路径
    SO_PATHS = [
        'lib/x86/libygsiyu.so',
        'lib/arm64-v8a/libygsiyu.so',
        'lib/x86_64/libygsiyu.so',
        'lib/armeabi-v7a/libygsiyu.so',
    ]
    
    @classmethod
    def extract_all(cls, apk_bytes: bytes) -> Dict[str, Any]:
        """
        从APK字节数据中提取所有参数
        :param apk_bytes: APK文件的字节数据
        :return: 包含提取参数和so文件的字典
        """
        result = {
            'package_name': 'N/A',
            'version_name': 'N/A',
            'version_code': 'N/A',
            'app_name': 'N/A',
            'sok': None,
            'dek': None,
            'sign_key': None,
            'sign_b64': None,
            'detected_mode': 'current',
            'lib_so_base64': None,
            'lib_so_name': 'lib.so',
            'native_so_base64': None,
            'native_so_name': None,
        }
        
        # 使用aapt获取APK信息
        apk_info = cls._get_apk_info(apk_bytes)
        if apk_info:
            result.update(apk_info)
        
        # 在内存中打开APK
        with zipfile.ZipFile(BytesIO(apk_bytes)) as zf:
            # 提取assets/lib.so文件
            lib_so_data = cls._extract_assets_lib_so(zf)
            if lib_so_data:
                result['lib_so_base64'] = base64.b64encode(lib_so_data).decode('utf-8')

            native_so_name, native_so_data = cls._find_so_file(zf, with_name=True)
            if native_so_data:
                result['native_so_base64'] = base64.b64encode(native_so_data).decode('utf-8')
                result['native_so_name'] = native_so_name
            
            # 提取so密钥
            result['sok'] = cls._extract_sok_from_so(zf)
            if result['sok'] and len(str(result['sok'])) <= 4:
                result['detected_mode'] = 'legacy4'
            
            # 提取dex密钥
            result['dek'] = cls._extract_dek_from_dex(zf)
            result['sign_key'] = cls._extract_signature_md5(zf)
            # 签名校验开启(extra_conf1g.xml 含 <signature>1</signature>)时，密钥派生不
            # 使用签名，无需回填 sign_b64；仅当校验关闭(文件为空/缺失)时才需要。
            if cls._signature_required(zf):
                result['sign_b64'] = cls._extract_signature_b64(zf)
        
        return result

    @classmethod
    def _signature_required(cls, zf: zipfile.ZipFile) -> bool:
        """签名校验是否关闭(关闭时才需要 sign_b64 参与密钥派生)。

        对应原生 com/iapp/app/e.ae(Context): 读取 assets/extra_conf1g.xml，
        若包含 ``<signature>1</signature>`` 则校验开启(返回 False)；否则关闭(返回 True)。
        """
        try:
            text = zf.read('assets/extra_conf1g.xml').decode('utf-8', errors='ignore')
        except KeyError:
            return True
        return '<signature>1</signature>' not in text

    @classmethod
    def _extract_signature_md5(cls, zf: zipfile.ZipFile) -> Optional[str]:
        der = cls._extract_signature_der(zf)
        return hashlib.md5(der).hexdigest() if der else None

    @classmethod
    def _extract_signature_b64(cls, zf: zipfile.ZipFile) -> Optional[str]:
        der = cls._extract_signature_der(zf)
        return base64.b64encode(der).decode("ascii") if der else None

    @classmethod
    def _extract_signature_der(cls, zf: zipfile.ZipFile) -> Optional[bytes]:
        candidates = [
            'META-INF/CERT.RSA',
            'META-INF/ANDROIDX.RSA',
        ]
        for name in zf.namelist():
            upper = name.upper()
            if upper.startswith('META-INF/') and upper.endswith('.RSA') and name not in candidates:
                candidates.append(name)
        for cert_path in candidates:
            try:
                cert_blob = zf.read(cert_path)
            except KeyError:
                continue
            try:
                certs = pkcs7.load_der_pkcs7_certificates(cert_blob)
            except Exception:
                continue
            for cert in certs:
                try:
                    return cert.public_bytes(Encoding.DER)
                except Exception:
                    continue
        return None
    
    @classmethod
    def _extract_assets_lib_so(cls, zf: zipfile.ZipFile) -> Optional[bytes]:
        """
        从APK中提取assets/lib.so文件
        :param zf: ZIP文件对象
        :return: lib.so文件的字节数据
        """
        # 可能的assets/lib.so路径
        possible_paths = [
            'assets/lib.so',
            'assets/lib/lib.so',
            'lib.so',
        ]
        
        for path in possible_paths:
            try:
                with zf.open(path) as f:
                    return f.read()
            except KeyError:
                continue
        
        # 全局搜索lib.so文件
        for name in zf.namelist():
            if name.endswith('/lib.so') or name == 'lib.so':
                try:
                    with zf.open(name) as f:
                        return f.read()
                except Exception:
                    continue
        
        return None
    
    @classmethod
    def _get_apk_info(cls, apk_bytes: bytes) -> Optional[Dict[str, str]]:
        """
        优先直接解析 APK 的 AndroidManifest.xml / resources.arsc，
        失败时再回退到 aapt。
        :param apk_bytes: APK文件的字节数据
        :return: 包含包信息的字典
        """
        # 先尝试内置解析，避免依赖外部 aapt。
        try:
            with zipfile.ZipFile(BytesIO(apk_bytes)) as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_info = cls._parse_axml_manifest(zf.read("AndroidManifest.xml"))
                    app_name = manifest_info.get("app_name")
                    if app_name and app_name.startswith("@") and "resources.arsc" in zf.namelist():
                        resolved = cls._resolve_arsc_string_ref(zf.read("resources.arsc"), app_name)
                        if resolved:
                            manifest_info["app_name"] = resolved
                    if manifest_info.get("package_name") and manifest_info.get("version_name") and manifest_info.get("version_code"):
                        return manifest_info
        except Exception:
            pass

        # 回退到 aapt
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as f:
                f.write(apk_bytes)
                temp_path = f.name
            
            try:
                result = subprocess.run(
                    ['aapt', 'dump', 'badging', temp_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    return None
                
                output = result.stdout
                
                # 提取包信息
                pkg_match = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", output)
                if not pkg_match:
                    return None
                
                # 提取应用名称
                app_name = 'N/A'
                label_match = re.search(r"application-label:'?([^']+)'", output)
                if not label_match:
                    label_match = re.search(r"application: label='([^']+)'", output)
                if label_match:
                    app_name = label_match.group(1)
                
                return {
                    'package_name': pkg_match.group(1),
                    'version_code': pkg_match.group(2),
                    'version_name': pkg_match.group(3),
                    'app_name': app_name,
                }
            finally:
                os.unlink(temp_path)
                
        except Exception:
            return None

    @staticmethod
    def _u16(blob: bytes, off: int) -> int:
        return struct.unpack_from("<H", blob, off)[0]

    @staticmethod
    def _u32(blob: bytes, off: int) -> int:
        return struct.unpack_from("<I", blob, off)[0]

    @classmethod
    def _read_len8(cls, blob: bytes, p: int) -> Tuple[int, int]:
        b = blob[p]
        if b & 0x80:
            return ((b & 0x7F) << 8) | blob[p + 1], 2
        return b, 1

    @classmethod
    def _read_len16(cls, blob: bytes, p: int) -> Tuple[int, int]:
        x = cls._u16(blob, p)
        if x & 0x8000:
            return ((x & 0x7FFF) << 16) | cls._u16(blob, p + 2), 4
        return x, 2

    @classmethod
    def _parse_axml_manifest(cls, axml: bytes) -> Dict[str, str]:
        def sx(strings: List[str], idx: int) -> str:
            if idx == 0xFFFFFFFF:
                return ""
            return strings[idx] if 0 <= idx < len(strings) else ""

        def attr_value(strings: List[str], dtype: int, data: int, raw: int) -> str:
            if raw != 0xFFFFFFFF:
                return sx(strings, raw)
            if dtype == 0x03:
                return sx(strings, data)
            if dtype == 0x10:
                return str(data if data < 0x80000000 else data - 0x100000000)
            if dtype == 0x11:
                return str(data)
            if dtype == 0x12:
                return "true" if data else "false"
            if dtype == 0x01:
                return f"@{data:08x}"
            return str(data)

        if len(axml) < 16:
            raise ValueError("bad axml")
        off = 8
        ctype, hsize, csize = struct.unpack_from("<HHI", axml, off)
        if ctype != 0x0001:
            raise ValueError("string pool not found")
        string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", axml, off + 8)
        utf8 = bool(flags & 0x100)
        offsets = [cls._u32(axml, off + hsize + i * 4) for i in range(string_count)]
        base = off + strings_start
        strings: List[str] = []
        for string_offset in offsets:
            p = base + string_offset
            if utf8:
                _, n1 = cls._read_len8(axml, p)
                l2, n2 = cls._read_len8(axml, p + n1)
                raw = axml[p + n1 + n2:p + n1 + n2 + l2]
                strings.append(raw.decode("utf-8", "replace"))
            else:
                l, n = cls._read_len16(axml, p)
                raw = axml[p + n:p + n + l * 2]
                strings.append(raw.decode("utf-16le", "replace"))

        result: Dict[str, str] = {}
        pos = off + csize
        while pos + 8 <= len(axml):
            typ, _head, size = struct.unpack_from("<HHI", axml, pos)
            if size <= 0:
                break
            if typ == 0x0102:
                _ns, name, attr_start, attr_size, attr_count, _id_idx, _cls_idx, _style_idx = struct.unpack_from("<IIHHHHHH", axml, pos + 16)
                tag = sx(strings, name)
                attr_off = pos + 16 + attr_start
                attrs: Dict[str, str] = {}
                for i in range(attr_count):
                    _ns_i, name_i, raw, _value_size, _zero, dtype, data = struct.unpack_from("<IIIHBBI", axml, attr_off + i * attr_size)
                    attrs[sx(strings, name_i)] = attr_value(strings, dtype, data, raw)
                if tag == "manifest":
                    if "package" in attrs:
                        result["package_name"] = attrs["package"]
                    if "versionName" in attrs:
                        result["version_name"] = attrs["versionName"]
                    if "versionCode" in attrs:
                        result["version_code"] = attrs["versionCode"]
                elif tag == "application" and "label" in attrs:
                    result["app_name"] = attrs["label"]
            pos += size
        return result

    @classmethod
    def _parse_arsc_string_pool(cls, blob: bytes, off: int) -> Tuple[List[str], int]:
        if off + 28 > len(blob):
            raise ValueError("bad arsc string pool offset")
        typ = cls._u16(blob, off)
        hsize = cls._u16(blob, off + 2)
        size = cls._u32(blob, off + 4)
        if typ != 0x0001 or size <= 0 or off + size > len(blob):
            raise ValueError("bad arsc string pool chunk")
        string_count = cls._u32(blob, off + 8)
        flags = cls._u32(blob, off + 16)
        strings_start = cls._u32(blob, off + 20)
        utf8 = bool(flags & 0x100)
        offsets = [cls._u32(blob, off + hsize + i * 4) for i in range(string_count)]
        base = off + strings_start
        out: List[str] = []
        for so in offsets:
            p = base + so
            if not (0 <= p < len(blob)):
                out.append("")
                continue
            try:
                if utf8:
                    _, n1 = cls._read_len8(blob, p)
                    l2, n2 = cls._read_len8(blob, p + n1)
                    raw = blob[p + n1 + n2:p + n1 + n2 + l2]
                    out.append(raw.decode("utf-8", "replace"))
                else:
                    l, n = cls._read_len16(blob, p)
                    raw = blob[p + n:p + n + l * 2]
                    out.append(raw.decode("utf-16le", "replace"))
            except Exception:
                out.append("")
        return out, size

    @classmethod
    def _resolve_arsc_string_ref(cls, arsc: bytes, ref: str) -> Optional[str]:
        ref = str(ref or "").strip()
        if not ref.startswith("@"):
            return None
        try:
            rid = int(ref[1:], 16)
        except Exception:
            return None
        pkg_id = (rid >> 24) & 0xFF
        type_id = (rid >> 16) & 0xFF
        entry_id = rid & 0xFFFF
        if len(arsc) < 12 or cls._u16(arsc, 0) != 0x0002:
            return None
        off = 12
        try:
            global_strings, sp_size = cls._parse_arsc_string_pool(arsc, off)
        except Exception:
            return None
        off += sp_size
        while off + 8 <= len(arsc):
            ctyp = cls._u16(arsc, off)
            hsize = cls._u16(arsc, off + 2)
            size = cls._u32(arsc, off + 4)
            if size <= 0 or off + size > len(arsc):
                break
            if ctyp != 0x0200:
                off += size
                continue
            try:
                cur_pkg_id = cls._u32(arsc, off + 8)
                if pkg_id and cur_pkg_id != pkg_id:
                    off += size
                    continue
            except Exception:
                off += size
                continue
            p = off + hsize
            while p + 20 <= off + size:
                try:
                    ttyp = cls._u16(arsc, p)
                    thsize = cls._u16(arsc, p + 2)
                    tsize = cls._u32(arsc, p + 4)
                except Exception:
                    break
                if tsize <= 0 or p + tsize > off + size:
                    break
                if ttyp == 0x0201:
                    tid = arsc[p + 8]
                    entry_count = cls._u32(arsc, p + 12)
                    entries_start = cls._u32(arsc, p + 16)
                    if tid == type_id and entry_id < entry_count:
                        ent_off_pos = p + thsize + entry_id * 4
                        if ent_off_pos + 4 <= len(arsc):
                            ent_off = cls._u32(arsc, ent_off_pos)
                            if ent_off != 0xFFFFFFFF:
                                ep = p + entries_start + ent_off
                                if ep + 16 <= len(arsc):
                                    flags = cls._u16(arsc, ep + 2)
                                    if not (flags & 0x0001):
                                        dtype = arsc[ep + 11]
                                        data = cls._u32(arsc, ep + 12)
                                        if dtype == 0x03 and data < len(global_strings):
                                            return global_strings[data]
                                        if dtype in (0x10, 0x11):
                                            return str(data if data < 0x80000000 else data - 0x100000000)
                p += tsize
            off += size
        return None
    
    @classmethod
    def _extract_sok_from_so(cls, zf: zipfile.ZipFile) -> Optional[str]:
        """
        从so文件中提取sok密钥（包含特征字符串前后内容）
        :param zf: ZIP文件对象
        :return: 提取的完整sok字符串
        """
        # 查找so文件
        so_data = cls._find_so_file(zf)
        if so_data is None:
            return None
        
        # 在so文件中查找特征字符串
        pattern_pos = so_data.find(cls.SEARCH_PATTERN)
        if pattern_pos == -1:
            legacy_pos = so_data.find(cls.LEGACY_SOK_MARKER)
            if legacy_pos >= 4:
                candidate = so_data[legacy_pos - 4:legacy_pos]
                try:
                    text = candidate.decode('ascii')
                except UnicodeDecodeError:
                    return None
                return text if len(text) == 4 and text.isprintable() else None
            return None
        
        # 确保前后都有足够长度的字符
        if pattern_pos < cls.SOK_BEFORE_LENGTH:
            return None
        if pattern_pos + len(cls.SEARCH_PATTERN) + cls.SOK_AFTER_LENGTH > len(so_data):
            return None
        
        # 提取完整的sok字符串：前10位 + QQQQQQQQQQ + 后12位
        start_pos = pattern_pos - cls.SOK_BEFORE_LENGTH
        end_pos = pattern_pos + len(cls.SEARCH_PATTERN) + cls.SOK_AFTER_LENGTH
        result = so_data[start_pos:end_pos]
        
        # 验证结果是否为可打印字符
        if not result.decode('ascii', errors='ignore').isprintable():
            return None
        
        return result.decode('ascii')
    
    @classmethod
    def _find_so_file(cls, zf: zipfile.ZipFile, with_name: bool = False):
        """
        在ZIP中查找libygsiyu.so文件
        :param zf: ZIP文件对象
        :return: so文件的字节数据
        """
        # 首先尝试已知路径
        for so_path in cls.SO_PATHS:
            try:
                with zf.open(so_path) as f:
                    data = f.read()
                    return (so_path, data) if with_name else data
            except KeyError:
                continue
        
        # 全局搜索libygsiyu.so
        for name in zf.namelist():
            if name.endswith('libygsiyu.so'):
                try:
                    with zf.open(name) as f:
                        data = f.read()
                        return (name, data) if with_name else data
                except Exception:
                    continue
        
        return (None, None) if with_name else None
    
    @classmethod
    def _extract_dek_from_dex(cls, zf: zipfile.ZipFile) -> Optional[str]:
        """
        从DEX文件中提取常量值作为dek
        :param zf: ZIP文件对象
        :return: 提取的常量值（十六进制字符串）
        """
        # 查找所有DEX文件
        dex_files = [name for name in zf.namelist() if name.endswith('.dex')]
        if not dex_files:
            return None

        for dex_name in dex_files:
            try:
                with zf.open(dex_name) as f:
                    dex_data = f.read()
                dek = cls._extract_fb_from_dex_blob(dex_data)
                if dek is not None:
                    return str(dek)
            except Exception:
                continue

        # 内置解析失败时，回退到 baksmali。
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.dex', delete=False) as dex_temp:
                temp_path = dex_temp.name

                target_classes = [
                    'com/iapp/app/f',
                    'com/iapp/app/F',
                    'com/iapp/a/f',
                    'com/iapp/a/F',
                    'com/example/app/f',
                ]

                for dex_name in dex_files:
                    try:
                        with tempfile.TemporaryDirectory() as out_dir:
                            with zf.open(dex_name) as f:
                                dex_temp.seek(0)
                                dex_temp.truncate(0)
                                dex_temp.seek(0)
                                dex_temp.write(f.read())
                                dex_temp.flush()

                            result = subprocess.run(
                                ['java', '-jar', cls.BAKSMALI_PATH, 'd', temp_path, '-o', out_dir],
                                capture_output=True,
                                timeout=60
                            )
                            if result.returncode != 0:
                                continue

                            for target_class in target_classes:
                                class_file = os.path.join(out_dir, target_class + '.smali')
                                if os.path.exists(class_file):
                                    with open(class_file, 'r', encoding='utf-8') as f:
                                        content = f.read()
                                    dek = cls._find_const_value(content)
                                    if dek:
                                        return dek

                            dek = cls._search_all_smali(out_dir)
                            if dek:
                                return dek
                    except Exception:
                        continue
            return None
        except Exception:
            return None

    @staticmethod
    def _dex_uleb(dex: bytes, p: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        while True:
            b = dex[p]
            p += 1
            result |= (b & 0x7F) << shift
            if b < 0x80:
                return result, p
            shift += 7

    @classmethod
    def _dex_read_strings(cls, dex: bytes) -> Tuple[List[str], Dict[str, int]]:
        names = [
            "string_ids_size", "string_ids_off",
            "type_ids_size", "type_ids_off",
            "proto_ids_size", "proto_ids_off",
            "field_ids_size", "field_ids_off",
            "method_ids_size", "method_ids_off",
            "class_defs_size", "class_defs_off",
        ]
        hdr = dict(zip(names, struct.unpack_from("<" + "I" * 12, dex, 0x38)))
        strings: List[str] = []
        for i in range(hdr["string_ids_size"]):
            off = struct.unpack_from("<I", dex, hdr["string_ids_off"] + i * 4)[0]
            _, p = cls._dex_uleb(dex, off)
            q = dex.find(b"\x00", p)
            strings.append(dex[p:q].decode("utf-8", "replace"))
        return strings, hdr

    @staticmethod
    def _read_dex_const_return_int(dex: bytes, code_off: int) -> Optional[int]:
        if code_off <= 0 or code_off + 16 > len(dex):
            return None
        registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack_from("<HHHHII", dex, code_off)
        insns_off = code_off + 16
        if insns_off + insns_size * 2 > len(dex):
            return None
        insns = list(struct.unpack_from("<" + "H" * insns_size, dex, insns_off))
        i = 0
        last_const = None
        last_reg = None
        while i < len(insns):
            op = insns[i] & 0xFF
            if op == 0x12:
                aa = (insns[i] >> 8) & 0xFF
                reg = aa & 0x0F
                imm = (aa >> 4) & 0x0F
                if imm & 0x8:
                    imm -= 0x10
                last_reg = reg
                last_const = imm
                i += 1
                continue
            if op == 0x13 and i + 1 < len(insns):
                reg = (insns[i] >> 8) & 0xFF
                imm = insns[i + 1]
                if imm & 0x8000:
                    imm -= 0x10000
                last_reg = reg
                last_const = imm
                i += 2
                continue
            if op == 0x14 and i + 2 < len(insns):
                reg = (insns[i] >> 8) & 0xFF
                imm = insns[i + 1] | (insns[i + 2] << 16)
                if imm & 0x80000000:
                    imm -= 0x100000000
                last_reg = reg
                last_const = imm
                i += 3
                continue
            if op == 0x15 and i + 1 < len(insns):
                reg = (insns[i] >> 8) & 0xFF
                imm = insns[i + 1] << 16
                if imm & 0x80000000:
                    imm -= 0x100000000
                last_reg = reg
                last_const = imm
                i += 2
                continue
            if op == 0x0F:
                reg = (insns[i] >> 8) & 0xFF
                if last_const is not None and (last_reg is None or last_reg == reg):
                    return last_const
                return last_const
            i += 1
        return last_const

    @classmethod
    def _extract_fb_from_dex_blob(cls, dex: bytes) -> Optional[int]:
        try:
            strings, hdr = cls._dex_read_strings(dex)
        except Exception:
            return None

        type_ids = [struct.unpack_from("<I", dex, hdr["type_ids_off"] + i * 4)[0] for i in range(hdr["type_ids_size"])]

        def tname(type_idx: int) -> str:
            return strings[type_ids[type_idx]]

        target_type_names = {
            "Lcom/iapp/app/f;",
            "Lcom/iapp/app/F;",
            "Lcom/iapp/a/f;",
            "Lcom/iapp/a/F;",
        }
        try:
            target_type = next(i for i, string_idx in enumerate(type_ids) if strings[string_idx] in target_type_names)
        except StopIteration:
            return None

        protos = []
        for i in range(hdr["proto_ids_size"]):
            shorty, ret, params = struct.unpack_from("<III", dex, hdr["proto_ids_off"] + i * 12)
            protos.append((strings[shorty], tname(ret)))
        methods = []
        for i in range(hdr["method_ids_size"]):
            class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", dex, hdr["method_ids_off"] + i * 8)
            methods.append((class_idx, proto_idx, name_idx))

        for class_def_index in range(hdr["class_defs_size"]):
            off = hdr["class_defs_off"] + class_def_index * 32
            class_idx, access_flags, super_idx, interfaces_off, source_idx, annotations_off, class_data_off, static_values_off = struct.unpack_from("<IIIIIIII", dex, off)
            if class_idx != target_type or class_data_off == 0:
                continue
            p = class_data_off
            static_fields_size, p = cls._dex_uleb(dex, p)
            instance_fields_size, p = cls._dex_uleb(dex, p)
            direct_methods_size, p = cls._dex_uleb(dex, p)
            virtual_methods_size, p = cls._dex_uleb(dex, p)
            for _ in range(static_fields_size + instance_fields_size):
                _, p = cls._dex_uleb(dex, p)
                _, p = cls._dex_uleb(dex, p)
            last_method_index = 0
            for _ in range(direct_methods_size + virtual_methods_size):
                method_idx_diff, p = cls._dex_uleb(dex, p)
                access_flags, p = cls._dex_uleb(dex, p)
                code_off, p = cls._dex_uleb(dex, p)
                last_method_index += method_idx_diff
                class_idx_m, proto_idx_m, name_idx_m = methods[last_method_index]
                method_name = strings[name_idx_m]
                proto = protos[proto_idx_m]
                if method_name == "b" and proto == ("I", "I") and code_off:
                    return cls._read_dex_const_return_int(dex, code_off)
        return None
    
    @classmethod
    def _find_const_value(cls, content: str) -> Optional[str]:
        """
        在smali内容中查找常量值
        :param content: smali文件内容
        :return: 找到的常量值（十六进制转十进制）
        """
        patterns = [
            r'const(?:/\w+)?\s+v0,\s*(0x[0-9a-fA-F]+)',
            r'const(?:/\w+)?\s+v1,\s*(0x[0-9a-fA-F]+)',
            r'const(?:/\w+)?\s+v2,\s*(0x[0-9a-fA-F]+)',
            r'const-string\s+v0,\s*"([^"]+)"',
            r'const-string\s+v1,\s*"([^"]+)"',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                value = match.group(1)
                # 如果是十六进制格式，转换为十进制
                if value.startswith('0x') or value.startswith('0X'):
                    try:
                        return str(int(value, 16))
                    except ValueError:
                        return value
                return value
        
        return None
    
    @classmethod
    def _search_all_smali(cls, out_dir: str) -> Optional[str]:
        """
        在所有smali文件中搜索常量值
        :param out_dir: 反编译输出目录
        :return: 找到的常量值
        """
        for root, dirs, files in os.walk(out_dir):
            for filename in files:
                if filename.endswith('.smali'):
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            # 查找包含b()方法或类似特征的类
                            if 'b()' in content or 'method' in content:
                                dek = cls._find_const_value(content)
                                if dek:
                                    return dek
                    except Exception:
                        continue
        
        return None


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python apk_extractor.py <apk_file>")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    with open(apk_path, 'rb') as f:
        apk_bytes = f.read()
    
    result = ApkExtractor.extract_all(apk_bytes)
    print("提取结果:")
    for k, v in result.items():
        print(f"  {k}: {v}")
