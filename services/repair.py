#!/usr/bin/env python3
"""
动态源码修复，自动根据特征找到映射类，提取数组，然后结合源码选择最优映射
"""
import ast
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from io import BytesIO
from typing import Dict, Iterable, List, Optional, Tuple

from config import REPAIR_DIR


SUPPORTED_TEXT_SUFFIXES = (
    ".iyu", ".myu", ".ilua", ".mlua", ".ijava", ".mjava", ".ijs", ".mjs",
    ".txt", ".lua", ".js", ".java", ".xml", ".json", ".html", ".htm", ".css",
)

BAKSMALI_JAR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tool", "baksmali.jar")

METHOD_START_RE = re.compile(r"^\s*\.method\b")
METHOD_END_RE = re.compile(r"^\s*\.end method\b")
CONST_STRING_RE = re.compile(r'^\s*const-string(?:/jumbo)?\s+([vp]\d+),\s+"((?:[^"\\]|\\.)*)"')
CONST_INT_RE = re.compile(r"^\s*const(?:/\d+)?(?:/high16)?\s+([vp]\d+),\s+(-?0x[0-9a-fA-F]+|-?\d+)\b")
NEW_ARRAY_RE = re.compile(r"^\s*new-array\s+([vp]\d+),\s+[vp]\d+,\s+\[Ljava/lang/String;")
APUT_RE = re.compile(r"^\s*aput-object\s+([vp]\d+),\s+([vp]\d+),\s+([vp]\d+)")
FILLED_NEW_ARRAY_RANGE_RE = re.compile(r"^\s*filled-new-array/range\s+\{([vp]\d+)\s+\.\.\s+([vp]\d+)\},\s+\[Ljava/lang/String;")
FILLED_NEW_ARRAY_RE = re.compile(r"^\s*filled-new-array\s+\{([^}]*)\},\s+\[Ljava/lang/String;")
INT_TO_STRING_RE = re.compile(
    r"^\s*invoke-static\s+\{([vp]\d+)\},\s+Ljava/lang/(?:Integer;->toString|String;->valueOf)\(I\)Ljava/lang/String;"
)
MOVE_RESULT_RE = re.compile(r"^\s*move-result-object\s+([vp]\d+)")
NEW_STRING_BUFFER_RE = re.compile(r"^\s*new-instance\s+([vp]\d+),\s+Ljava/lang/(?:StringBuffer|StringBuilder);")
STRING_BUFFER_INIT_RE = re.compile(
    r"^\s*invoke-direct\s+\{([vp]\d+),\s*([vp]\d+)\},\s+Ljava/lang/(?:StringBuffer|StringBuilder);-><init>\(Ljava/lang/String;\)V"
)
STRING_BUFFER_APPEND_CHAR_RE = re.compile(
    r"^\s*invoke-virtual\s+\{([vp]\d+),\s*([vp]\d+)\},\s+Ljava/lang/(?:StringBuffer|StringBuilder);->append\(C\)Ljava/lang/(?:StringBuffer|StringBuilder);"
)
STRING_BUFFER_APPEND_STRING_RE = re.compile(
    r"^\s*invoke-virtual\s+\{([vp]\d+),\s*([vp]\d+)\},\s+Ljava/lang/(?:StringBuffer|StringBuilder);->append\(Ljava/lang/String;\)Ljava/lang/(?:StringBuffer|StringBuilder);"
)
STRING_BUFFER_TO_STRING_RE = re.compile(
    r"^\s*invoke-virtual\s+\{([vp]\d+)\},\s+Ljava/lang/(?:StringBuffer|StringBuilder);->toString\(\)Ljava/lang/String;"
)


@dataclass
class RepairResult:
    mapping: Dict[str, str]
    modified_files: List[dict]
    replaced_count: int
    output_zip_bytes: bytes
    preview_map: List[dict]
    dex_count: int


def _decode_smali_string(raw: str) -> str:
    try:
        return ast.literal_eval('"' + raw.replace('"', '\\"') + '"')
    except Exception:
        return raw.encode("utf-8", errors="ignore").decode("unicode_escape", errors="ignore")


def _parse_smali_int(raw: str) -> Optional[int]:
    try:
        return int(raw, 16) if raw.lower().startswith("0x") or raw.lower().startswith("-0x") else int(raw, 10)
    except ValueError:
        return None


def _extract_string_arrays_from_smali(smali_text: str) -> List[List[str]]:
    """从单个 smali 文件内容里提取所有字符串数组"""
    arrays: List[List[str]] = []
    string_regs: Dict[str, str] = {}
    int_regs: Dict[str, int] = {}
    array_regs: Dict[str, Dict[int, str]] = {}
    buffer_regs: Dict[str, str] = {}
    pending_string_value: Optional[str] = None
    in_method = False

    for raw_line in smali_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if METHOD_START_RE.match(line):
            in_method = True
            string_regs = {}
            int_regs = {}
            array_regs = {}
            buffer_regs = {}
            pending_string_value = None
            continue

        if METHOD_END_RE.match(line):
            for items in array_regs.values():
                if items:
                    ordered = [items[idx] for idx in sorted(items)]
                    if len(ordered) >= 2:
                        arrays.append(ordered)
            in_method = False
            continue

        if not in_method:
            continue

        match = CONST_STRING_RE.match(line)
        if match:
            string_regs[match.group(1)] = _decode_smali_string(match.group(2))
            continue

        match = CONST_INT_RE.match(line)
        if match:
            value = _parse_smali_int(match.group(2))
            if value is not None:
                int_regs[match.group(1)] = value
            continue

        match = FILLED_NEW_ARRAY_RANGE_RE.match(line)
        if match:
            start_reg, end_reg = match.groups()
            if start_reg[0] == end_reg[0]:
                start_idx = int(start_reg[1:])
                end_idx = int(end_reg[1:])
                ordered = []
                for idx in range(start_idx, end_idx + 1):
                    reg = f"{start_reg[0]}{idx}"
                    value = string_regs.get(reg)
                    if value is None:
                        ordered = []
                        break
                    ordered.append(value)
                if len(ordered) >= 2:
                    arrays.append(ordered)
            continue

        match = FILLED_NEW_ARRAY_RE.match(line)
        if match:
            ordered = []
            for reg in [item.strip() for item in match.group(1).split(",") if item.strip()]:
                value = string_regs.get(reg)
                if value is None:
                    ordered = []
                    break
                ordered.append(value)
            if len(ordered) >= 2:
                arrays.append(ordered)
            continue

        match = NEW_ARRAY_RE.match(line)
        if match:
            array_regs.setdefault(match.group(1), {})
            continue

        match = INT_TO_STRING_RE.match(line)
        if match:
            reg = match.group(1)
            value = int_regs.get(reg)
            pending_string_value = str(value) if value is not None else None
            continue

        match = NEW_STRING_BUFFER_RE.match(line)
        if match:
            buffer_regs[match.group(1)] = ""
            continue

        match = STRING_BUFFER_INIT_RE.match(line)
        if match:
            buffer_reg, source_reg = match.groups()
            if source_reg in string_regs:
                buffer_regs[buffer_reg] = string_regs[source_reg]
            continue

        match = STRING_BUFFER_APPEND_CHAR_RE.match(line)
        if match:
            buffer_reg, source_reg = match.groups()
            if buffer_reg in buffer_regs and source_reg in int_regs:
                try:
                    buffer_regs[buffer_reg] += chr(int_regs[source_reg])
                except ValueError:
                    pass
            continue

        match = STRING_BUFFER_APPEND_STRING_RE.match(line)
        if match:
            buffer_reg, source_reg = match.groups()
            if buffer_reg in buffer_regs and source_reg in string_regs:
                buffer_regs[buffer_reg] += string_regs[source_reg]
            continue

        match = STRING_BUFFER_TO_STRING_RE.match(line)
        if match:
            buffer_reg = match.group(1)
            pending_string_value = buffer_regs.get(buffer_reg)
            continue

        match = MOVE_RESULT_RE.match(line)
        if match and pending_string_value is not None:
            string_regs[match.group(1)] = pending_string_value
            pending_string_value = None
            continue

        match = APUT_RE.match(line)
        if match:
            value_reg, array_reg, index_reg = match.groups()
            if array_reg not in array_regs:
                continue
            if value_reg not in string_regs or index_reg not in int_regs:
                continue
            array_regs[array_reg][int_regs[index_reg]] = string_regs[value_reg]

    return arrays


def _get_all_smali_files(root_dir: str) -> List[str]:
    """递归获取目录下所有 smali 文件"""
    out = []
    for current_root, _dirs, files in os.walk(root_dir):
        for name in files:
            if name.endswith(".smali"):
                out.append(os.path.join(current_root, name))
    return out


def _light_scan_smali_for_mapping_features(smali_path: str) -> int:
    """轻量扫描单个 smali 文件，返回特征分数，越高越可能是映射类"""
    score = 0
    has_f_const = False
    has_numeric_const = False
    has_fill_array_data = False
    has_codelist_field = False
    is_v4_or_aid_yucode = False
    is_likely_library = False

    basename = os.path.basename(smali_path).lower()
    dirname = os.path.dirname(smali_path).lower()
    if "androidx" in dirname or "kotlin" in dirname or "kotlinx" in dirname or "com/google" in dirname or "okhttp" in dirname or "retrofit" in dirname:
        is_likely_library = True
    if "v4" in basename or "aid_yucode" in basename or "yucode" in basename:
        is_v4_or_aid_yucode = True

    try:
        with open(smali_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_strip = line.strip()
                if not line_strip:
                    continue
                if ".field" in line_strip and "codelist" in line_strip.lower():
                    has_codelist_field = True
                if ".field" in line_strip and ("map" in line_strip.lower() or "func" in line_strip.lower()):
                    has_codelist_field = True
                if 'const-string' in line_strip:
                    if '"f(' in line_strip or '"ss ' in line_strip or '"s ' in line_strip or '"sss ' in line_strip or '"for(' in line_strip or '"w(' in line_strip or '"t(' in line_strip:
                        has_f_const = True
                    if re.search(r'"\d+\(', line_strip) or re.search(r'"\d+"', line_strip):
                        has_numeric_const = True
                if "fill-array-data" in line_strip or "filled-new-array" in line_strip:
                    has_fill_array_data = True
    except Exception:
        pass

    if is_v4_or_aid_yucode:
        score += 1000
    if has_codelist_field:
        score += 500
    if has_f_const and has_fill_array_data:
        score += 300
    if has_f_const:
        score += 150
    if has_numeric_const:
        score += 100
    if has_fill_array_data:
        score += 80
    if len(os.path.basename(smali_path)) <= 6:
        score += 20
    if is_likely_library:
        score = max(0, score - 200)

    return score


def _scan_smali_files_for_mapping_candidates(out_dir: str, top_k: int = 15) -> List[str]:
    """扫描反汇编目录，按特征分数排序，返回最可能是映射类的 smali 文件路径"""
    all_smali = _get_all_smali_files(out_dir)
    scored = []
    for smali_path in all_smali:
        score = _light_scan_smali_for_mapping_features(smali_path)
        if score > 0:
            scored.append((-score, smali_path, score))
    scored.sort()
    return [path for (_neg, path, _score) in scored[:top_k]]


def _extract_dl3_arrays_from_smali(smali_path: str) -> Optional[Tuple[List[str], List[str]]]:
    """
    从 Aid_YuCode.smali 或者类似的文件，专门解析 dl3 函数的两个分支，
    提取（原函数名数组和数字数组）
    """
    try:
        with open(smali_path, "r", encoding="utf-8", errors="ignore") as f:
            smali_text = f.read()
    except Exception:
        return None

    # 检查是不是包含 "dl3"
    if "dl3" not in smali_text:
        return None

    lines = smali_text.splitlines()

    # 找到 dl3 函数的开始和结束
    dl3_start = None
    dl3_end = None
    depth = 0
    for i, line in enumerate(lines):
        line = line.strip()
        if ".method" in line and "dl3" in line:
            dl3_start = i
            continue
        if dl3_start is not None:
            if ".method" in line:
                # 嵌套的？
                pass
            if ".end method" in line:
                dl3_end = i
                break

    if dl3_start is None or dl3_end is None:
        return None

    # 在 dl3 函数内部找两个 new-array 位置
    new_array_lines = []
    for i in range(dl3_start, dl3_end + 1):
        line = lines[i].strip()
        if "new-array" in line:
            new_array_lines.append(i)

    if len(new_array_lines) < 2:
        return None

    def parse_array_from_lines(start_line: int, end_line: int) -> List[str]:
        """从指定行范围里提取数组，处理 StringBuffer
        """
        registers = {}
        array = []
        in_array = False
        pending_str = None
        for i in range(start_line, end_line + 1):
            line = lines[i].strip()
            if not line or line.startswith(".line") or line.startswith(".registers") or line.startswith(":cond_"):
                continue
            if "return-object" in line:
                break
            if "new-array" in line:
                in_array = True
                continue
            if not in_array:
                continue

            # const string
            m = re.match(r'const-string(?:/jumbo)?\s+([vp]\d+),\s*"((?:[^"\\]|\\.)*)"', line)
            if m:
                reg, val = m.groups()
                val = val.replace('\\"', '"')
                registers[reg] = val
                continue

            # const number
            m = re.match(r'const(?:/[a-zA-Z0-9]+)?\s+([vp]\d+),\s*(0x[0-9a-fA-F]+|-?[0-9]+)', line)
            if m:
                reg, val_str = m.groups()
                if val_str.startswith('0x'):
                    val = int(val_str, 16)
                else:
                    val = int(val_str, 10)
                registers[reg] = val
                continue

            # new StringBuffer
            m = re.match(r'new-instance\s+([vp]\d+),\s+Ljava/lang/StringBuffer', line)
            if m:
                reg = m.group(1)
                registers[reg] = ''
                continue

            # init StringBuffer
            m = re.match(r'invoke-direct\s+\{([vp]\d+),\s*([vp]\d+)\},.*StringBuffer.*-><init>\(Ljava/lang/String;\)', line)
            if m:
                buf_reg, init_reg = m.groups()
                if init_reg in registers:
                    init_val = registers[init_reg]
                    if isinstance(init_val, int):
                        init_val = str(init_val)
                    registers[buf_reg] = init_val
                continue

            # append char
            m = re.match(r'invoke-virtual\s+\{([vp]\d+),\s*([vp]\d+)\},.*StringBuffer.*->append\(C\)', line)
            if m:
                buf_reg, char_reg = m.groups()
                if buf_reg in registers and char_reg in registers:
                    c = registers[char_reg]
                    if isinstance(c, int):
                        try:
                            registers[buf_reg] += chr(c)
                        except:
                            pass
                continue

            # toString
            m = re.match(r'invoke-virtual\s+\{([vp]\d+)\},.*StringBuffer.*->toString\(\)', line)
            if m:
                buf_reg = m.group(1)
                if buf_reg in registers:
                    pending_str = registers[buf_reg]
                continue

            # move result
            m = re.match(r'move-result-object\s+([vp]\d+)', line)
            if m and pending_str is not None:
                target_reg = m.group(1)
                registers[target_reg] = pending_str
                pending_str = None
                continue

            # aput
            m = re.match(r'aput-object\s+([vp]\d+),\s+([vp]\d+),\s+([vp]\d+)', line)
            if m:
                val_reg, _, idx_reg = m.groups()
                if idx_reg in registers and val_reg in registers:
                    idx = int(registers[idx_reg])
                    val = registers[val_reg]
                    if not isinstance(val, str):
                        val = str(val)
                    while len(array) <= idx:
                            array.append(None)
                    array[idx] = val
                continue

        return [x for x in array if x is not None]

    # 解析两个数组：
    # 第一个数组范围：从第一个 new-array，到第二个 new-array 之前
    arr1 = parse_array_from_lines(new_array_lines[0], new_array_lines[1] - 1)
    # 第二个数组范围：从第二个 new-array，到 dl3_end
    arr2 = parse_array_from_lines(new_array_lines[1], dl3_end)

    # 判断哪一个是数字数组，哪一个是原函数名数组
    arr1_numcount = sum(1 for x in arr1 if re.sub(r'\D', '', x))
    arr2_numcount = sum(1 for x in arr2 if re.sub(r'\D', '', x))

    if arr1_numcount > arr2_numcount:
        # arr1 是数字数组，arr2 是原函数名数组
        return (arr2, arr1)  # 返回 (原函数名数组, 数字数组)
    else:
        return (arr1, arr2)


def _extract_all_arrays_from_candidate_smali(smali_paths: List[str]) -> List[List[str]]:
    """从候选 smali 路径列表里提取所有字符串数组，还额外尝试 dl3 函数"""
    all_arrays = []
    for smali_path in smali_paths:
        try:
            with open(smali_path, "r", encoding="utf-8", errors="ignore") as f:
                arrays = _extract_string_arrays_from_smali(f.read())
                all_arrays.extend(arrays)
        except Exception:
            continue
        # 尝试 dl3 函数
        dl3_result = _extract_dl3_arrays_from_smali(smali_path)
        if dl3_result:
            arr_func, arr_num = dl3_result
            if arr_func:
                all_arrays.append(arr_func)
            if arr_num:
                all_arrays.append(arr_num)

    return all_arrays


def _extract_numeric_key(item: str) -> str:
    """从字符串里提取纯数字"""
    return re.sub(r"\D", "", (item or "").strip())


def _build_mapping_from_arrays(originals: List[str], numbers: List[str]) -> Dict[str, str]:
    """从两个数组建立映射：key是数字，value是原函数名（带(）"""
    mapping: Dict[str, str] = {}
    for idx in range(min(len(originals), len(numbers))):
        original = (originals[idx] or "").strip()
        number = _extract_numeric_key(numbers[idx])
        if not number or not original:
            continue
        if not original.endswith("("):
            original += "("
        mapping[number] = original
    return mapping


def _compile_repair_pattern(mapping: Dict[str, str]) -> re.Pattern[str]:
    if not mapping:
        raise ValueError("映射表为空")
    keys = sorted(mapping.keys(), key=len, reverse=True)
    return re.compile(r"(?<![\w])((" + "|".join(re.escape(k) for k in keys) + r"))\(")


def _estimate_mapping_hits_in_source_text(mapping: Dict[str, str], source_text: str) -> int:
    """估计映射在单份源码里的命中次数"""
    if not mapping:
        return 0
    pattern = _compile_repair_pattern(mapping)
    return len(pattern.findall(source_text))


def _estimate_mapping_hits_in_source_zip(mapping: Dict[str, str], src_zip_bytes: bytes) -> int:
    """估计映射在整个源码 zip 里的命中次数"""
    total = 0
    for text in _iter_source_texts(src_zip_bytes):
        total += _estimate_mapping_hits_in_source_text(mapping, text)
    return total


def _find_best_mapping_from_all_arrays(all_arrays: List[List[str]], src_zip_bytes: Optional[bytes] = None, extra_candidates: Optional[List[Dict[str, str]]] = None) -> Tuple[Dict[str, str], int]:
    """
    从所有数组里找最优映射
    :param all_arrays: 所有提取到的字符串数组
    :param src_zip_bytes: 如果有源码 zip，用命中次数选最好的
    :param extra_candidates: 预先准备好的候选映射，优先评估
    :return: (最佳映射, 命中次数)
    """
    candidates: List[Tuple[Dict[str, str], int]] = []
    seen_signatures = set()

    # 首先处理 extra_candidates
    if extra_candidates:
        for mapping in extra_candidates:
            if not mapping or len(mapping) < 3:
                continue
            signature = tuple(sorted(mapping.items()))
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)

            if src_zip_bytes:
                hits = _estimate_mapping_hits_in_source_zip(mapping, src_zip_bytes)
            else:
                has_f = any("f(" in v for v in mapping.values())
                hits = len(mapping) * (3 if has_f else 1)
            candidates.append((mapping, hits))

    # 然后把数组分成两组：可能的数字数组 vs 可能的原函数名数组
    numeric_array_candidates: List[List[str]] = []  # 里面大多是纯数字（或数字加(）的数组
    original_array_candidates: List[List[str]] = []  # 里面大多是非数字的数组（或包含 f(, ss , s 的）

    for arr in all_arrays:
        if len(arr) < 2:
            continue
        numeric_count = 0
        has_function_mark = False
        for item in arr:
            num_key = _extract_numeric_key(item)
            if num_key and len(num_key) >= 4:  # 至少4位数字才认为是混淆数字
                numeric_count += 1
            if "f(" in item or "ss " in item or "s " in item or "sss " in item or "syso(" in item:
                has_function_mark = True
        # 判断
        if numeric_count / len(arr) >= 0.4:
            numeric_array_candidates.append(arr)
        elif has_function_mark or numeric_count < len(arr) * 0.2:
            original_array_candidates.append(arr)

    # 如果我们没有明确的 original_array_candidates，或者 original_array_candidates 是空的
    # 那我们就尝试所有可能的数组对，交换位置
    all_pairs_to_try = []
    if numeric_array_candidates and original_array_candidates:
        for o_arr in original_array_candidates:
            for n_arr in numeric_array_candidates:
                all_pairs_to_try.append((o_arr, n_arr))
                all_pairs_to_try.append((n_arr, o_arr))  # 也试试交换位置
    else:
        for i, arr1 in enumerate(all_arrays):
            for arr2 in all_arrays[i+1:]:
                all_pairs_to_try.append((arr1, arr2))
                all_pairs_to_try.append((arr2, arr1))

    for o_arr, n_arr in all_pairs_to_try:
        mapping = _build_mapping_from_arrays(o_arr, n_arr)
        if not mapping or len(mapping) < 3:
            continue
        signature = tuple(sorted(mapping.items()))
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)

        if src_zip_bytes:
            hits = _estimate_mapping_hits_in_source_zip(mapping, src_zip_bytes)
        else:
            has_f = any("f(" in v for v in mapping.values())
            hits = len(mapping) * (3 if has_f else 1)
        candidates.append((mapping, hits))

    if not candidates:
        raise RuntimeError("未能生成任何候选映射")

    candidates.sort(key=lambda x: (-x[1], -len(x[0])))
    return candidates[0]


def _extract_mapping_candidates_from_single_dex(
    dex_bytes: bytes,
    src_zip_bytes: Optional[bytes] = None
) -> Tuple[Dict[str, str], int]:
    """从单个 dex 里提取最优映射"""
    if not dex_bytes:
        raise ValueError("dex 文件为空")
    if not os.path.exists(BAKSMALI_JAR):
        raise RuntimeError("缺少 baksmali.jar，无法解析 dex")
    if shutil.which("java") is None:
        raise RuntimeError("系统未找到 java，无法运行 baksmali")

    with tempfile.TemporaryDirectory(prefix="iapp_repair_") as temp_dir:
        dex_path = os.path.join(temp_dir, "classes.dex")
        out_dir = os.path.join(temp_dir, "smali")
        with open(dex_path, "wb") as f:
            f.write(dex_bytes)
        cmd = ["java", "-jar", BAKSMALI_JAR, "d", dex_path, "-o", out_dir]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError("baksmali 解析失败: " + (result.stdout.strip() or "unknown error"))
        candidate_smali_paths = _scan_smali_files_for_mapping_candidates(out_dir, top_k=15)

        # 首先，专门尝试找 dl3 的数组对
        dl3_arrays = None
        for smali_path in candidate_smali_paths:
            temp_dl3 = _extract_dl3_arrays_from_smali(smali_path)
            if temp_dl3:
                dl3_arrays = temp_dl3
                break

        all_arrays = _extract_all_arrays_from_candidate_smali(candidate_smali_paths)

        # 如果找到 dl3 的配对，就把这对候选映射放最前面
        extra_candidates = []
        if dl3_arrays:
            arr_func, arr_num = dl3_arrays
            m1 = _build_mapping_from_arrays(arr_func, arr_num)
            m2 = _build_mapping_from_arrays(arr_num, arr_func)
            if m1:
                extra_candidates.append(m1)
            if m2:
                extra_candidates.append(m2)

        # 现在，调用 _find_best_mapping_from_all_arrays，但传入 extra_candidates
        return _find_best_mapping_from_all_arrays(all_arrays, src_zip_bytes, extra_candidates)


def _iter_dex_entries(bundle_bytes: bytes, bundle_name: str = "") -> List[Tuple[str, bytes]]:
    """从 dex 或 zip/apk 里迭代所有 dex 文件"""
    name = (bundle_name or "").lower()
    if bundle_bytes[:3] == b"dex":
        return [(bundle_name or "classes.dex", bundle_bytes)]
    if bundle_bytes[:2] != b"PK" and not name.endswith((".zip", ".apk")):
        return [(bundle_name or "classes.dex", bundle_bytes)]

    entries: List[Tuple[str, bytes]] = []
    try:
        with zipfile.ZipFile(BytesIO(bundle_bytes), "r") as zf:
            for entry_name in sorted(zf.namelist()):
                base = os.path.basename(entry_name).lower()
                if re.fullmatch(r"classes\d*\.dex", base):
                    entries.append((entry_name, zf.read(entry_name)))
    except zipfile.BadZipFile as exc:
        raise RuntimeError("dex 压缩包格式无效") from exc
    if not entries:
        raise RuntimeError("压缩包中未找到 classes*.dex")
    return entries


def _decode_text(data: bytes) -> str:
    """自动尝试多种编码解码"""
    for encoding in ("utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")


def _should_repair_file(path: str) -> bool:
    """判断是否应该修复这个文件"""
    lower = path.lower()
    return any(lower.endswith(suffix) for suffix in SUPPORTED_TEXT_SUFFIXES)


def _iter_source_texts(src_zip_bytes: bytes) -> Iterable[str]:
    """迭代源码 zip 里所有需要修复的文件的内容"""
    with zipfile.ZipFile(BytesIO(src_zip_bytes), "r") as zf:
        for info in zf.infolist():
            if info.is_dir() or not _should_repair_file(info.filename):
                continue
            yield _decode_text(zf.read(info.filename))


def _repair_text(content: str, mapping: Dict[str, str], pattern: re.Pattern[str]) -> Tuple[str, int]:
    """修复单个文本内容"""
    def replace(match: re.Match[str]) -> str:
        return mapping[match.group(1)]
    return pattern.subn(replace, content)


def extract_mapping_from_dex_bundle(
    bundle_bytes: bytes,
    bundle_name: str = "",
    src_zip_bytes: Optional[bytes] = None
) -> Tuple[Dict[str, str], int]:
    """从 dex 包（zip/apk 或单个 dex）里提取最优映射"""
    entries = _iter_dex_entries(bundle_bytes, bundle_name)
    best_mapping: Dict[str, str] = {}
    best_hits = -1
    errors: List[str] = []

    for dex_name, dex_bytes in entries:
        try:
            mapping, hits = _extract_mapping_candidates_from_single_dex(dex_bytes, src_zip_bytes)
            if hits > best_hits or (hits == best_hits and len(mapping) > len(best_mapping)):
                best_mapping = mapping
                best_hits = hits
        except Exception as exc:
            errors.append(f"{dex_name}: {exc}")
            continue

    if not best_mapping:
        if errors:
            raise RuntimeError("所有 dex 提取映射失败: " + " | ".join(errors[:3]))
        raise RuntimeError("未能从 dex 包中提取到有效映射")
    return best_mapping, len(entries)


def repair_source_bundle(
    dex_bundle_bytes: bytes,
    src_zip_bytes: bytes,
    dex_bundle_name: str = ""
) -> RepairResult:
    """
    主入口：修复源码
    :param dex_bundle_bytes: dex zip/apk 或单个 dex 的字节内容
    :param src_zip_bytes: 待修复的源码 zip 的字节内容
    :param dex_bundle_name: dex 包的文件名
    :return: RepairResult 对象
    """
    mapping, dex_count = extract_mapping_from_dex_bundle(dex_bundle_bytes, dex_bundle_name, src_zip_bytes)
    pattern = _compile_repair_pattern(mapping)
    modified_files: List[dict] = []
    replaced_count = 0
    output_buffer = BytesIO()

    with zipfile.ZipFile(BytesIO(src_zip_bytes), "r") as src_zf, zipfile.ZipFile(
        output_buffer, "w", compression=zipfile.ZIP_DEFLATED
    ) as out_zf:
        for info in src_zf.infolist():
            if info.is_dir():
                out_zf.writestr(info, b"")
                continue
            raw_data = src_zf.read(info.filename)
            write_data = raw_data

            if _should_repair_file(info.filename):
                text = _decode_text(raw_data)
                repaired_text, count = _repair_text(text, mapping, pattern)
                if count > 0:
                    replaced_count += count
                    modified_files.append({"path": info.filename, "replaced": count})
                    write_data = repaired_text.encode("utf-8")

            clone = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            clone.compress_type = zipfile.ZIP_DEFLATED
            clone.comment = info.comment
            clone.extra = info.extra
            clone.create_system = info.create_system
            clone.external_attr = info.external_attr
            out_zf.writestr(clone, write_data)

    preview_pairs = [{"from": k, "to": v} for k, v in list(mapping.items())[:20]]

    return RepairResult(
        mapping=mapping,
        modified_files=modified_files,
        replaced_count=replaced_count,
        output_zip_bytes=output_buffer.getvalue(),
        preview_map=preview_pairs,
        dex_count=dex_count,
    )



def _repair_output_path(token: str) -> str:
    return os.path.join(REPAIR_DIR, f"{token}.zip")
def _save_repair_output(zip_bytes: bytes) -> str:
    os.makedirs(REPAIR_DIR, exist_ok=True)
    token = secrets.token_hex(16)
    with open(_repair_output_path(token), "wb") as f:
        f.write(zip_bytes)
    return token


# ---------- 请求处理 ----------
