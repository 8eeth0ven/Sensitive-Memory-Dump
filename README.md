# Sensitive-Memory-Dump

Authorized memory sensitive-information scanner for **Windows processes** and **Android apps**.

A general-purpose, authorization-scoped toolkit that **dumps a running process/app memory to a local file first**, then matches it with a **local regex engine** (ASCII + UTF-16LE dual-alignment) to pull out URLs, tokens, keys, AWS/Aliyun/Tencent AKs, JWTs, and dynamic JS/API paths. No frida / procdump / comsvcs / Sysinternals needed for the Windows path — pure `ctypes` WinAPI, only Python stdlib + admin.

> Only use on targets you own or have explicit authorization to test. Memory may contain other users' credentials / PII.

## Files

| File | Role |
|---|---|
| `PcDump.py` | **Windows PC** process scanner. Default = dump memory to a local `.bin`, then regex. Optional in-memory scan via `--live`. Includes a `frida` fallback mode. |
| `DroidDump.py` | **Android app** scanner. Reuses PcDump's engine. Attaches via frida gadget → dumps to device → adb pull → local regex (+ `rules.json`). |
| `mem_dump.js` | Frida agent: enumerates `r--/rw-/r-x` ranges and writes them to a device file. |
| `rules.json` | Dynamic-surface regex rules (new JS paths / API paths). Uses Burp HaE structure (`name / firstRegex / sensitive`). |

## Windows (PC) usage

```bash
python PcDump.py <pid>                 # winapi: dump to memdump.bin, then regex
python PcDump.py --pid <pid> --perm rw # only writable heap (fast, token/URL live there)
python PcDump.py --pid <pid> --dump raw.bin
python PcDump.py --src raw.bin         # regex an existing dump only, no process attach
python PcDump.py --mode frida <pid>    # fallback to frida attach
python PcDump.py --pid <pid> --live    # in-memory scan (may crash target; off by default)
```

## Android usage

```bash
python DroidDump.py --pkg com.example.app --out droid_sens
python DroidDump.py --pkg com.example.app --host 127.0.0.1:14725   # gadget port
python DroidDump.py --bin memdump.bin --out droid_sens            # regex only
```

## Notes

- Default is **dump-to-local then regex** (stable, re-runnable). In-memory scanning (`--live`) is opt-in and may crash the target process.
- UTF-16LE is matched with **0/1 byte-aligned** passes to avoid odd-offset misses.
- True positives must be reviewed (a 32-hex string may be an ID, not a secret).

---

授权范围内的内存敏感信息扫描工具：支持 **Windows 进程** 与 **Android App**。先 dump 到本地文件，再用本地正则（ASCII + UTF-16LE 双对齐）提取 URL / 令牌 / 密钥 / AK / JWT 以及动态 JS / API 路径。Windows 路径只需 Python 标准库 + 管理员权限。

> 仅限授权测试。内存可能包含其他用户的凭据 / 隐私。

| 文件 | 作用 |
|---|---|
| `PcDump.py` | Windows 进程扫描。默认先 dump 到本地 `.bin` 再正则；`--live` 内存内直扫；含 frida 降级。 |
| `DroidDump.py` | Android App 扫描。复用 PcDump 引擎，frida gadget → dump 设备 → adb pull → 本地正则。 |
| `mem_dump.js` | frida agent：枚举 `r--/rw-/r-x` 写到设备文件。 |
| `rules.json` | 动态面条规（新 JS / API 路径），Burp HaE 结构。 |

```bash
# PC
python PcDump.py <pid>
python PcDump.py --pid <pid> --perm rw

# Android
python DroidDump.py --pkg com.example.app
```
