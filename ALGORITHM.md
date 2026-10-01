# 解密原理（算法）

本文说明 iApp v3 加密包（`assets/lib.so`）的加解密结构与三种算法族的推导过程，对应源码：

- `crypto/` —— 密码学原语（`slky` 哈希、AES、ELF 解析）
- `algorithms/` —— 算法族（`current` / `legacy4` / `transitional`）与密钥候选工厂
- `services/decrypt.py` —— 解密调度入口

---

## 1. 整体结构：外层容器 + 内层成员

`lib.so` 是**两层结构**：

1. **外层容器**：`lib.so` 整体用 AES-CBC 加密，解密后得到一段「容器字节流」。
2. **内层成员**：容器里按 `开始标记 / 结束标记` 分隔出若干「成员」——每个成员是一个源码文件（`mian.iyu`、`xxx.myu`、`xxx.mlua` …），各自再独立解密。

解密流程：先解外层拿容器 → 解入口成员（`entry_file`，默认 `mian.iyu`）→ 从解出的源码里扫描引用（`fn xxx.myu`、`call(..., 'xxx.yul')`、`*.iyu` 等）→ 递归解密被引用的成员，直到没有新成员。

---

## 2. 密码学原语

### 2.1 `slky` —— 自定义哈希（`crypto/slky.py`）

不是标准哈希，是一个**有符号数学 + MD5 + 置换**的复合函数，签名：

```text
slky(input, secondary, post_key) -> 16 字节
```

步骤：

1. 对 `input` 做有符号统计：`first`、`last`、`signed_sum = Σ to_signed(b) + n`；
   `avg = signed_sum / n`、`seed = (signed_sum + last*first) / n`、`remainder = signed_sum % n`。
2. 拼接 `work = input + str(seed) + secondary`；若 `secondary` 非空，`remainder = (remainder + len(secondary)) & 0xFF`。
3. `work` 每个字节 `^= avg & 0xFF`。
4. `digest = MD5(work)`（16 字节）。
5. 置换：`v64 = (8 + remainder) & 0xFF`，对 `digest` 每个位置按 `abs(to_signed(digest[pos])) % 16` 交换；若交换下标 > 8 则 `^= v64`；若有 `post_key` 则再与 `post_key[pos % len]` 异或。

`slky` 用于**外层密钥派生**和**成员标记 / 成员密钥派生**，是整套算法的核心。

### 2.2 AES + 循环 XOR（`crypto/aes.py`）

- `aes_cbc_then_xor_decrypt(cipher, key)`：`AES-128-CBC`（密钥与 IV 都取 `key[:16]`）→ PKCS5 去填充 → 结果与 `key` 循环异或。
- `aes_cbc_decrypt_only(cipher, key)`：只做 AES-CBC + 去填充，**不异或**（transitional 族用）。
- `cyclic_xor(data, key)`：`data[i] ^ key[i % len(key)]`。

---

## 3. 三种算法族

`services/decrypt.py` 的 `decrypt_bundle` 按 `mode`（或 `auto`）分派。`auto` 的判定：`sok` 长度 ≤ 4 → `legacy4`，否则 → `current`。

| 家族 | 触发条件 | 状态 |
| --- | --- | --- |
| `current` | `sok` 长度 > 4（现代 iApp v3） | 已支持 |
| `legacy4` | `sok` 长度 ≤ 4（远古版本） | 已支持 |
| `transitional` | 过渡期 `iapp::mete::slky`（如 `1.apk` 蛟龙） | 遗留难题，仍未攻克 |

### 3.1 current（现代）

**外层密钥**由 `algorithms/factory.py::generate_outer_candidates` 生成一系列候选 `OuterCandidate`，每个候选用 `idbfj_seed` 派生：

```text
deriv   = base + password            # base = sok + version_name + package_name + app_name + version_code + dek
case_idx = signed_mod(signed_sum(deriv) + to_signed(deriv[0]) * to_signed(deriv[-1]), 6)
second  = [version_name, package_name, app_name, version_code, sok, dek][case_idx]
outer_key = slky(deriv, second, post_key)
```

候选遍历不同的 `(password_name, mode, post_mode, transform)` 组合（`EnvP25Candidate`、`LegacyOuterCandidate`、`NativeX86IdbfjP25Candidate`、带签名的 `...SignatureCandidate` 等），按 `confidence` 排序逐一尝试。

```text
container = aes_cbc_then_xor_decrypt(lib_so, outer_key)
```

**成员解密**（`algorithms/common.py`）：

```text
start_marker = slky(name, sok + dek, marker_post_key)
end_marker   = slky(name, dek + sok, marker_post_key)
blob         = container[start_marker : end_marker]     # 两个标记之间的密文

seed        = slky(name + sok + dek, name, member_post_key)
member_key  = cyclic_xor(seed, xor_key)[:16]            # xor 模式；direct 模式直接 seed[:16]
plain       = aes_cbc_then_xor_decrypt(blob, member_key)
```

**验证**：`looks_like_iapp_plain` 检查明文是否含 iApp 源码特征（`<View`、`function`、`fn `、`call(`、`dim `、`syso(` 等）。命中才认为该候选正确。

### 3.2 legacy4（远古）

密钥派生走 `md5` 链（`algorithms/legacy4.py`）：

```text
app_key      = md5(app_name + version_name + package_name + version_code)
half_lib_key = md5(dek + sok + app_key + sign_key + pwd_key)
```

成员分隔标记：

```text
start_marker = base64(md5(so_key + "iapp"  + index))
end_marker   = base64(md5(so_key + "ysiapp" + index))
```

成员载荷是 base64 的 AES-CBC 密文，签名 / 密码候选由 `sign_key`（证书 md5 派生或 `null`）与 `pwd_key`（`md5(raw + "mmpfbf")` 或空）组合枚举。

### 3.3 transitional（过渡期 mete，未完成）

对应 `iapp::mete::slky` + `iapp::burden::b`，特点是 **post_key 为空、pick6 用 unsigned、AES 不做 xor**：

```text
p19 = slky(first, second, None)
p24 = slky(signature, p19, None)    # 签名校验关闭时；否则 slky(p19, p19, None)
p25 = slky(p19, p24, None)
container = aes_cbc_decrypt_only(lib_so, p25)
```

成员与 `current` 同构但 `post_key=None`、`aes_cbc_decrypt_only`。此族（`1.apk` 蛟龙）仍解密失败，是独立待解难题。

---

## 4. 密钥来源（post_key / xor_key）

`algorithms/factory.py::generate_key_sets` 组装候选，交叉穷举（各取前 8，最多 64 组合）：

- **post_key**：内置 `MAGIC_BYTES`（20 字节）→ 从 `native_so`（`libygsiyu.so`）用 `crypto/elf.py` 静态分析提取 → 手动传入。
- **xor_key**：内置 `BURDEN_XOR_KEY`（20 字节）→ 从 `native_so` 提取 → 手动传入。

**ELF 密钥提取**（`crypto/elf.py`）：解析 `libygsiyu.so` 的 ELF，定位引用 `.rodata` 的函数（AArch64 `adrp+ldr/add`、x86-64 RIP 相对 `lea/mov/movdqa`、ARM `ldr pc`），把函数引用的 16~96 字节二进制表当作 `post_key` / `xor_key` 候选，按长度/熵排序取前若干。

---

## 5. 参数来源（`/extract_apk`）

`services/apk_extract.py` 从 APK 自动提取解密所需参数：

| 参数 | 来源 |
| --- | --- |
| `package_name` / `version_name` / `version_code` / `app_name` | `AndroidManifest.xml`（aapt 解析） |
| `sok` | `libygsiyu.so` 中的特征字符串（`crypto/sok.py`） |
| `dek` | `classes.dex` 反编译（`tool/baksmali.jar`） |
| `sign_key` / `sign_b64` | APK 签名（`META-INF` 的 DER，md5 或 base64） |
| `lib_so` / `native_so` | `assets/lib.so` 与 `lib/*/libygsiyu.so` |

---

## 6. 参考

- 完整 API 见 [`api.md`](api.md) 与在线文档 <https://iapp.0d0d.top/docs.html>
- 成品网站 <https://iapp.0d0d.top>
