"""全局配置常量。"""
import re

MAGIC_STRING = bytes([
    0xE2, 0x5F, 0x48, 0x73, 0x25, 0xC6, 0xE7, 0x11, 0x80, 0x7C,
    0x46, 0xC3, 0xE3, 0x1D, 0x3C, 0x97, 0x3C, 0x8C, 0x1E, 0x01,
])
MAGIC_BYTES = bytes([
    0xE2, 0x5F, 0x48, 0x73, 0x25, 0xC6, 0xE7, 0x11, 0x80, 0x7C,
    0x46, 0xC3, 0xE3, 0x1D, 0x3C, 0x97, 0x3C, 0x77, 0x1E, 0x01,
])
BURDEN_XOR_KEY = bytes([
    0xE2, 0x48, 0x25, 0xE7, 0x80, 0x46, 0xE3, 0x3C, 0x3C, 0x1E,
    0x25, 0x1D, 0x4E, 0x05, 0x55, 0xE1, 0x69, 0xA8, 0x18, 0xCA,
])

# 公共密钥（多版本）：
# - old  : K_SLKY_OLD / BURDEN_XOR_KEY
# - new  : K_SLKY_NEW / K_XOR_NEW
# - new2 : K_SLKY_V2 / K_XOR_V2
K_SLKY_OLD = bytes.fromhex("e25f487325c6e711807c46c3e31d3c977c771e01")
K_SLKY_NEW = bytes.fromhex("07dad9c1553c1bfb6d885b919baab0fe58a042c21b489d3673259407754407c54b97cee4c8")
K_XOR_NEW = bytes.fromhex("07d9551b6d5b9bb058421b9d739475074bcec8da177937bdc7d7e4a2bdcd2704")
K_SLKY_V2 = bytes.fromhex("afdeb9ee7b003855b352ec9fa6a41ed97cf5b7f3d9").split(b"\x00")[0]
K_XOR_V2 = bytes.fromhex("afb97b38b3eca61e7cb7d9e336153a9c8c03355085").split(b"\x00")[0]

REFERENCE_SUFFIXES = ("iyu", "myu", "ilua", "mlua", "ijava", "mjava", "ijs", "mjs", "java", "yul", "html")
EXT_PATTERN = "|".join(REFERENCE_SUFFIXES)
REFERENCE_PATTERN = re.compile(rf"(?i)([A-Za-z0-9_./\-\u4e00-\u9fa5]+\.(?:{EXT_PATTERN}))")
FN_PATTERN = re.compile(r"(?i)fn\s+([A-Za-z0-9_/\-\u4e00-\u9fa5]+)\.[A-Za-z0-9_/\-\u4e00-\u9fa5]+")
CALL_PATTERN = re.compile(r"(?i)call\s*\([^,]+,\s*[\"\']([^\"\']+)[\"\']\s*,\s*[\"\']([A-Za-z0-9_/\-\u4e00-\u9fa5]+)\.[^\"\']+[\"\']")
HIDDEN_PATTERN = re.compile(rb"[A-Za-z0-9]{10}Q{10}W{10}EE")
LEGACY_LOCAL_MARKER = "=/eyVRDWJWJF4zIwoyZyZPfQ=="
LEGACY_OLD_SO_MARKER = b"\x00aa\x00lib.so"
LEGACY_DEFAULT_SIGN_KEY = "null"
LEGACY_DEFAULT_PWD_KEY = ""
LEGACY_HIDDEN_OUTPUTS = {"import.mjs", "import.mlua"}
LEGACY_WZYANG_JMXY_3 = "mmpygs93"
LEGACY_WZYANG_JMXY_4 = "mmpfbf"

# iApp 用户加密（密码加密）固定盐：logoActivity$a 里 password + "mmpfbf" 再 MD5，
# 结果作为 user_enc 拼进 idbfj 的 base 尾部（current/legacy 通用）。
USER_PWD_SALT = "mmpfbf"
LEGACY_REFERENCE_RE = re.compile(
    r"([A-Za-z0-9_\-\u4e00-\u9fa5./]+\.(?:iyu|ijava|ilua|ijs|myu|mjava|mlua|mjs))"
    r"|(fn [A-Za-z0-9_\-\u4e00-\u9fa5]+)"
    r"|(call\(.*\))",
    re.IGNORECASE,
)
LEGACY_CALL_MODULE_RE = re.compile(r"([A-Za-z0-9_\-\u4e00-\u9fa5]+\.)")


import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
TOOL_DIR = os.path.join(PROJECT_ROOT, "tool")
BAKSMALI_JAR = os.path.join(TOOL_DIR, "baksmali.jar")
# 所有运行时数据统一放到 data/ 目录，避免在项目根目录散落一堆文件夹
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
LOG_DIR = os.path.join(DATA_DIR, "logs")
LOGS_JSON_PATH = os.path.join(DATA_DIR, "logs.json")
CACHE_DIR = os.path.join(DATA_DIR, "decrypt_cache")
REPAIR_DIR = os.path.join(DATA_DIR, "repair_output")
UPLOAD_TMP_DIR = os.path.join(DATA_DIR, "upload_tmp")
UPLOAD_STORE_DIR = os.path.join(DATA_DIR, "upload_store")
UPLOAD_CHUNK_SIZE = 2 * 1024 * 1024
UPLOAD_MAX_SIZE = 512 * 1024 * 1024
