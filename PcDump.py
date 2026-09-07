# -*- coding: utf-8 -*-
"""PcDump.py — Windows 进程内存敏感信息扫描器（先 dump 到本地，再正则匹配）

双路模式（--mode）：
  winapi  (默认)  纯 Windows API(ctypes)：OpenProcess + VirtualQueryEx + ReadProcessMemory
                  把目标进程内存【先 dump 到本地文件】，再由本地正则引擎扫描。
                  不依赖 frida / procdump / comsvcs / Sysinternals 等任何外部或厂商工具，
                  只需 Python 标准库 + 管理员权限即可独立完成。
  frida  (可选)  降级用 frida 注入 agent 内存内扫描（需本地安装 frida 且能 attach）。

本地正则引擎与 Android 端 DroidDump.py 共用（复用）。规则：ASCII + UTF-16LE(0/1 双对齐) 下的
URL / 关键词 / 特殊格式(AWS·阿里·腾讯·JWT·UUID·邮箱·手机号)。

用法：
  python PcDump.py 19864                      winapi，先 dump 到 <out>/memdump.bin 再扫
  python PcDump.py --pid 19864 --perm rw     只扫可写堆区(快，token 所在)
  python PcDump.py --pid 19864 --dump raw.bin 指定 dump 文件
  python PcDump.py --src raw.bin             只扫已有 dump，不再碰进程
  python PcDump.py --mode frida 1234         降级用 frida 附加扫描
  python PcDump.py --pid 19864 --test "http" 先做一次字符串定位验证
"""

import os
import re
import sys
import time
import argparse
from datetime import datetime
from collections import defaultdict

# frida 仅在 --mode frida 时才加载，winapi 路径不依赖它
try:
    import frida
except Exception:
    frida = None

DEFAULT_PID = 19864

# ============================================================================
# 扫描规则（与 frida agent 对齐，纯 Python 实现，供本地文件扫描使用）
# ============================================================================
URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}[/a-zA-Z0-9_.\-\?\&\=%]*")

KEYWORDS = [
    "username", "user_name", "user", "userid", "user_id", "uid", "usr",
    "uname", "un", "account", "acct", "acc", "login_name", "login_account",
    "password", "passwd", "pwd", "pw", "pass", "passphrase", "passcode",
    "token", "access_token", "refresh_token", "api_token", "auth_token",
    "session", "session_id", "sessionid", "sid", "sess",
    "cookie", "cookies", "authorization", "auth", "bearer",
    "api_key", "apikey", "api_secret", "ak", "sk",
    "verification_code", "verify_code", "auth_code", "sms_code", "captcha", "code",
]

SPECIAL_PATTERNS = [
    ("AWS_AK", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("ALIYUN_AK", re.compile(r"LTAI[0-9A-Za-z]{12,20}")),
    ("TENCENT_AK", re.compile(r"AKID[0-9A-Za-z]{13,20}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("UUID", re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")),
    ("EMAIL", re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")),
    ("PHONE_CN", re.compile(r"1[3-9][0-9]{9}")),
]


def build_keyword_pattern(kw):
    """对应 JS buildKeywordPattern：key=value / key: value / "key":"value"。"""
    escaped = re.escape(kw)
    return re.compile(
        r'["\']?' + escaped + r'["\']?\s*[:=]\s*["\']?([^"\'\s,;\}\]\r\n]{1,256})["\']?',
        re.IGNORECASE,
    )


def extract_ascii(data):
    """对应 JS extractAscii：可打印 ASCII 保留，其余占位空格。"""
    return "".join(chr(b) if 0x20 <= b <= 0x7E else " " for b in data)


def extract_utf16le(data, offset=0):
    """按两字节一组解释小端宽字符。offset 支持 0/1 两种字节对齐，避免奇偶错位漏检。"""
    out = []
    for i in range(offset, len(data) - 1, 2):
        code = data[i] | (data[i + 1] << 8)
        out.append(chr(code) if 0x20 <= code <= 0x7E else " ")
    return "".join(out)


class MemoryScannerBase:
    """扫描引擎：对一块文本执行 URL / 关键词 / 特殊格式，并去重。"""

    def __init__(self):
        self.results = []
        self._seen = set()

    def _add(self, rtype, keyword, value, address, encoding):
        if not value:
            return
        value = value.strip()
        if len(value) < 2 or len(value) > 1024:
            return
        key = rtype + "|" + keyword + "|" + value[:64]
        if key in self._seen:
            return
        self._seen.add(key)
        self.results.append({
            "type": rtype, "keyword": keyword, "value": value,
            "address": address, "encoding": encoding,
        })

    def scan_text(self, text, base_addr, encoding):
        """base_addr 为文件偏移或地区基址；encoding 决定地址单位。"""
        if not text or len(text) < 10:
            return
        unit = 2 if encoding == "UTF16LE" else 1
        for m in URL_PATTERN.finditer(text):
            self._add("URL", "", m.group(0), hex(base_addr + m.start() * unit), encoding)
        for kw in KEYWORDS:
            pat = build_keyword_pattern(kw)
            for m in pat.finditer(text):
                val = m.group(1) or m.group(0)
                self._add("KEYWORD", kw, val, hex(base_addr + m.start() * unit), encoding)
        for name, pat in SPECIAL_PATTERNS:
            for m in pat.finditer(text):
                self._add(name, "", m.group(0), hex(base_addr + m.start() * unit), encoding)


def enable_se_debug_privilege():
    """尽力开启 SeDebugPrivilege（需管理员），别让它因权限直接读不到。非致命。"""
    try:
        import ctypes
        from ctypes import wintypes
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", ctypes.c_long)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        SE_PRIVILEGE_ENABLED = 0x2
        TOKEN_ADJUST = 0x20
        TOKEN_QUERY = 0x8
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                         TOKEN_ADJUST | TOKEN_QUERY, ctypes.byref(token)):
            return False
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
        return True
    except Exception:
        return False


def scan_file(path, engine, chunk=1024 * 1024):
    """本地正则：对 dump 下来的 bin 分块扫描，填充 engine.results。返回扫描字节数。"""
    total = 0
    with open(path, "rb") as f:
        while True:
            blk = f.read(chunk)
            if not blk:
                break
            engine._scan_bytes(blk, total)
            total += len(blk)
    return total


class WinapiScanner(MemoryScannerBase):
    """纯 Windows API 读内存并 dump 到本地文件（自包含，无外部工具）。"""

    MEM_COMMIT = 0x1000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100
    _WRITE = (0x04, 0x08, 0x40, 0x80)  # READWRITE/WRITECOPY/EXEC_READWRITE/EXEC_WRITECOPY

    def __init__(self, pid, output_file="keyword.txt", chunk=1024 * 1024, perm="all"):
        super().__init__()
        self.pid = pid
        self.output_file = output_file
        self.chunk = chunk
        self.perm = perm          # "all"=全部可读;"rw"=仅可写堆区(提速)
        self.handle = None

    def _MBI(self):
        import ctypes
        from ctypes import wintypes

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]
        return MEMORY_BASIC_INFORMATION

    def open_process(self):
        import ctypes
        from ctypes import wintypes
        self.kernel32 = ctypes.windll.kernel32
        k = self.kernel32
        k.OpenProcess.restype = wintypes.HANDLE
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.VirtualQueryEx.restype = ctypes.c_size_t
        k.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        k.ReadProcessMemory.restype = wintypes.BOOL
        k.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        handle = k.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid)
        if not handle:
            err = ctypes.get_last_error()
            raise PermissionError(
                "OpenProcess(%d) 失败 (last_error=%d)。目标进程不存在、或权限不足（需管理员）。"
                "若为受保护进程(如 LSASS/SAM)需 SeDebugPrivilege，普通模式通常读不了。" % (self.pid, err))
        self.handle = handle
        return handle

    def _regions(self):
        import ctypes
        k = self.kernel32
        MBI = self._MBI()
        addr = 0
        while True:
            mbi = MBI()
            nbytes = k.VirtualQueryEx(self.handle, ctypes.c_void_p(addr),
                                      ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not nbytes:
                break
            base = int(mbi.BaseAddress or 0)
            size = mbi.RegionSize
            if size and base:
                yield base, size, mbi.State, mbi.Protect
            addr = base + size
            if size == 0 or addr > (2 ** 64) - size:
                break

    def _read(self, addr, size):
        import ctypes
        k = self.kernel32
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        ok = k.ReadProcessMemory(self.handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(read))
        return buf.raw[:int(read.value)] if ok and read.value else None

    def _selected(self, state, protect):
        if state != self.MEM_COMMIT:
            return False
        if protect & (self.PAGE_NOACCESS | self.PAGE_GUARD):
            return False
        if self.perm == "rw" and (protect & 0xFF) not in self._WRITE:
            return False
        return True

    def dump_to_file(self, path, max_regions=0):
        """把选定内存 dump 到本地文件。返回 {regions, bytes, errors, skipped}。"""
        stats = {"regions": 0, "bytes": 0, "errors": 0, "skipped": 0}
        with open(path, "wb") as fh:
            for base, size, state, protect in self._regions():
                if not self._selected(state, protect):
                    stats["skipped"] += 1
                    continue
                if size > 128 * 1024 * 1024:
                    stats["skipped"] += 1
                    continue
                stats["regions"] += 1
                off = 0
                while off < size:
                    step = min(self.chunk, size - off)
                    data = self._read(base + off, step)
                    if data:
                        fh.write(data)
                        stats["bytes"] += len(data)
                    else:
                        stats["errors"] += 1
                        break
                    off += step
                if max_regions and stats["regions"] >= max_regions:
                    break
        return stats

    def scan_live(self, max_regions=0):
        """内存内直接扫（不落盘）。⚠️ 目标进程易崩/易卡，仅 --live 触发；
        【默认】走 dump_to_file + scan_file 更稳。"""
        stats = {"regions": 0, "bytes": 0, "errors": 0, "skipped": 0}
        for base, size, state, protect in self._regions():
            if not self._selected(state, protect):
                stats["skipped"] += 1
                continue
            if size > 128 * 1024 * 1024:
                stats["skipped"] += 1
                continue
            stats["regions"] += 1
            off = 0
            while off < size:
                step = min(self.chunk, size - off)
                data = self._read(base + off, step)
                if data:
                    stats["bytes"] += len(data)
                    self._scan_bytes(data, base + off)
                else:
                    stats["errors"] += 1
                    break
                off += step
            if max_regions and stats["regions"] >= max_regions:
                break
        return stats

    def _scan_bytes(self, data, base_addr):
        self.scan_text(extract_ascii(data), base_addr, "ASCII")
        # UTF-16LE 用 0/1 两种字节对齐各扫一遍，避免 ASCII 与 UTF-16 混杂/奇偶错位漏检
        for off in (0, 1):
            self.scan_text(extract_utf16le(data, off), base_addr + off, "UTF16LE")

    def search_string(self, target):
        """在进程内存定位目标字符串（ASCII + UTF-16LE），用于验证读取是否成功。"""
        raw = target.encode("utf-8")
        utf16 = target.encode("utf-16-le")
        found = []
        for base, size, state, protect in self._regions():
            if not self._selected(state, protect) or size > 64 * 1024 * 1024:
                continue
            data = self._read(base, size)
            if not data:
                continue
            for needle, enc in ((raw, "ASCII"), (utf16, "UTF16LE")):
                start = 0
                while True:
                    idx = data.find(needle, start)
                    if idx < 0:
                        break
                    found.append((hex(base + idx), enc))
                    start = idx + 1
        return found

    def close(self):
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None


class FridaScanner(MemoryScannerBase):
    """降级路径：用 frida 附加目标进程，由 agent 内存内扫描。"""

    FRIDA_SCRIPT = r"""
'use strict';
const results = [];
const foundSet = new Set();
const URL_PATTERN = /https?:\/\/[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}[\/a-zA-Z0-9_.\-\?\&\=\%]*/g;
const KEYWORDS = [
    'username','user_name','user','userid','user_id','uid','usr',
    'uname','un','account','acct','acc','login_name','login_account',
    'password','passwd','pwd','pw','pass','passphrase','passcode',
    'token','access_token','refresh_token','api_token','auth_token',
    'session','session_id','sessionid','sid','sess',
    'cookie','cookies','authorization','auth','bearer',
    'api_key','apikey','api_secret','ak','sk',
    'verification_code','verify_code','auth_code','sms_code','captcha','code'
];
const SPECIAL_PATTERNS = [
    { name: 'AWS_AK', pattern: /AKIA[0-9A-Z]{16}/g },
    { name: 'ALIYUN_AK', pattern: /LTAI[0-9A-Za-z]{12,20}/g },
    { name: 'TENCENT_AK', pattern: /AKID[0-9A-Za-z]{13,20}/g },
    { name: 'JWT', pattern: /eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g },
    { name: 'UUID', pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g },
    { name: 'EMAIL', pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g },
    { name: 'PHONE_CN', pattern: /1[3-9][0-9]{9}/g }
];
function buildKeywordPattern(kw){ var e=kw.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'); return new RegExp('["\']?'+e+'["\']?\\s*[:=]\\s*["\']?([^"\'\\s,;\\}\\]\\r\\n]{1,256})["\']?','gi'); }
function addResult(type,keyword,value,address,encoding){
    if(!value||value.length<2) return; value=value.trim();
    if(value.length<2||value.length>1024) return;
    var key=type+'|'+keyword+'|'+value.substring(0,64);
    if(foundSet.has(key)) return; foundSet.add(key);
    results.push({type:type,keyword:keyword,value:value,address:address,encoding:encoding});
}
function extractAscii(buffer){ var b=new Uint8Array(buffer), s=''; for(var i=0;i<b.length;i++){var x=b[i]; s+= x>=0x20&&x<=0x7E?String.fromCharCode(x):' ';} return s; }
function extractUtf16Le(buffer,offset){ offset=offset||0; var b=new Uint8Array(buffer), s=''; for(var i=offset;i<b.length-1;i+=2){var c=b[i]|(b[i+1]<<8); s+= c>=0x20&&c<=0x7E?String.fromCharCode(c):' ';} return s; }
function scanContent(str,base,enc){
    if(!str||str.length<10) return; var m,unit=enc==='UTF16LE'?2:1;
    URL_PATTERN.lastIndex=0; while((m=URL_PATTERN.exec(str))!==null){ addResult('URL','',m[0],base.add(m.index*unit).toString(),enc); }
    for(var i=0;i<KEYWORDS.length;i++){ var kw=KEYWORDS[i],p=buildKeywordPattern(kw); p.lastIndex=0; while((m=p.exec(str))!==null){ addResult('KEYWORD',kw,m[1]||m[0],base.add(m.index*unit).toString(),enc); } }
    for(var j=0;j<SPECIAL_PATTERNS.length;j++){ var sp=SPECIAL_PATTERNS[j]; sp.pattern.lastIndex=0; while((m=sp.pattern.exec(str))!==null){ addResult(sp.name,'',m[0],base.add(m.index*unit).toString(),enc); } }
}
function scanRegion(base,size){ try{ var buffer=Memory.readByteArray(base,size); if(!buffer) return; scanContent(extractAscii(buffer),base,'ASCII'); scanContent(extractUtf16Le(buffer,0),base,'UTF16LE'); scanContent(extractUtf16Le(buffer,1),base.add(1),'UTF16LE'); }catch(e){} }
function fullScan(){ results.length=0; foundSet.clear(); var stats={regionsScanned:0,bytesScanned:0,errors:0}; var allRanges=[];
    Process.enumerateRanges('r--').forEach(r=>allRanges.push(r));
    Process.enumerateRanges('rw-').forEach(r=>allRanges.push(r));
    Process.enumerateRanges('r-x').forEach(r=>allRanges.push(r));
    var seen=new Set(), unique=allRanges.filter(r=>{var k=r.base.toString(); if(seen.has(k))return false; seen.add(k); return true;});
    for(var i=0;i<unique.length;i++){ var range=unique[i]; if(range.size>128*1024*1024) continue;
        var chunkSize=1024*1024; for(var off=0;off<range.size;off+=chunkSize){ var size=Math.min(chunkSize,range.size-off);
            try{ scanRegion(range.base.add(off),size); stats.bytesScanned+=size; }catch(e){ stats.errors++; } }
        stats.regionsScanned++; }
    return {stats:stats, resultCount:results.length};
}
rpc.exports={ scan:fullScan, getResults:function(){return results;}, searchString:function(t){
    var f=[],b=[],u=[]; for(var i=0;i<t.length;i++){b.push(t.charCodeAt(i)); u.push(t.charCodeAt(i),0);}
    var all=[]; Process.enumerateRanges('r--').forEach(r=>all.push(r)); Process.enumerateRanges('rw-').forEach(r=>all.push(r));
    for(var j=0;j<all.length;j++){ var rg=all[j]; if(rg.size>64*1024*1024) continue; try{
        var ma=Memory.scanSync(rg.base,rg.size,b.map(x=>x.toString(16).padStart(2,'0')).join(' '));
        ma.forEach(m=>f.push({address:m.address.toString(),encoding:'ASCII'}));
        var mu=Memory.scanSync(rg.base,rg.size,u.map(x=>x.toString(16).padStart(2,'0')).join(' '));
        mu.forEach(m=>f.push({address:m.address.toString(),encoding:'UTF16LE'}));
    }catch(e){} }
    return f;
} };
"""

    def __init__(self, pid, output_file="keyword.txt"):
        super().__init__()
        self.pid = pid
        self.output_file = output_file
        self.session = None
        self.script = None

    def attach(self):
        if frida is None:
            raise RuntimeError("未安装 frida。请 `pip install frida` 后再用 --mode frida；或用默认 --mode winapi。")
        self.session = frida.attach(self.pid)
        self.script = self.session.create_script(self.FRIDA_SCRIPT)
        self.script.load()
        return True

    def scan(self):
        res = self.script.exports_sync.scan()
        self.results = self.script.exports_sync.get_results()
        return res

    def search_string(self, target):
        return self.script.exports_sync.search_string(target)

    def close(self):
        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass


# ============================================================================
# 报告输出（两路共用）
# ============================================================================
def export_results(results, pid, output_file):
    if not results:
        return None
    output_path = os.path.abspath(output_file)
    by_type = defaultdict(list)
    for r in results:
        by_type[r["type"]].append(r)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("  内存扫描报告\n")
        f.write("  时间: %s\n" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        f.write("  目标: %s\n" % pid)
        f.write("  总数: %d\n" % len(results))
        f.write("=" * 80 + "\n")

        if "URL" in by_type:
            urls = by_type["URL"]
            f.write("\n%s\n  [URL] 共 %d 条\n%s\n\n" % ("=" * 80, len(urls), "=" * 80))
            for url in sorted(set(u["value"] for u in urls)):
                f.write("  %s\n" % url)

        if "KEYWORD" in by_type:
            f.write("\n%s\n  [关键词] 共 %d 条\n%s\n" % ("=" * 80, len(by_type["KEYWORD"]), "=" * 80))
            by_kw = defaultdict(list)
            for k in by_type["KEYWORD"]:
                by_kw[k["keyword"]].append(k)
            for kw, items in sorted(by_kw.items()):
                f.write("\n  [%s] - %d 条\n" % (kw, len(items)))
                f.write("  " + "-" * 60 + "\n")
                seen = set()
                for item in items:
                    if item["value"] not in seen:
                        seen.add(item["value"])
                        f.write("    %s\n" % item["value"])
                        f.write("    @ %s (%s)\n\n" % (item["address"], item["encoding"]))

        for t in by_type:
            if t in ("URL", "KEYWORD"):
                continue
            items = by_type[t]
            f.write("\n%s\n  [%s] 共 %d 条\n%s\n\n" % ("=" * 80, t, len(items), "=" * 80))
            seen = set()
            for item in items:
                if item["value"] not in seen:
                    seen.add(item["value"])
                    f.write("  %s\n" % item["value"])
                    f.write("  @ %s (%s)\n\n" % (item["address"], item["encoding"]))

        f.write("\n%s\n  统计摘要\n%s\n\n" % ("=" * 80, "=" * 80))
        stats = defaultdict(int)
        for r in results:
            if r["type"] == "KEYWORD":
                stats["KEYWORD:%s" % r["keyword"]] += 1
            else:
                stats[r["type"]] += 1
        for t, c in sorted(stats.items(), key=lambda x: -x[1]):
            f.write("  %s: %d\n" % (t, c))
    return output_path


def print_summary(results, pid):
    total = len(results)
    print("\n" + "=" * 60)
    print("  扫描完成 | 目标: %s | 共发现 %d 个问题" % (pid, total))
    print("=" * 60)
    if total > 0:
        stats = defaultdict(int)
        for r in results:
            if r["type"] == "KEYWORD":
                stats["KEYWORD:%s" % r["keyword"]] += 1
            else:
                stats[r["type"]] += 1
        print("\n  分类统计:")
        for t, c in sorted(stats.items(), key=lambda x: -x[1])[:15]:
            print("    %s: %d" % (t, c))
    print()


def _parse_args():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pid", nargs="?", default=DEFAULT_PID, help="目标 PID（默认 %d）" % DEFAULT_PID)
    ap.add_argument("--pid", dest="pid_opt", help="目标 PID（与位置参数等价）")
    ap.add_argument("--mode", choices=["winapi", "frida"], default="winapi",
                    help="winapi=纯 WinAPI 自包含(默认)；frida=frida 注入 agent(降级)")
    ap.add_argument("-o", "--out", default="keyword.txt", help="输出报告文件（默认 keyword.txt）")
    ap.add_argument("--perm", choices=["all", "rw"], default="all",
                    help="winapi 模式：rw=只 dump/扫可写堆区(快，token 所在)；all=全部可读(默认)")
    ap.add_argument("--dump", default=None, help="winapi：dump 到本地文件的路径(默认 <out 目录>/memdump.bin)")
    ap.add_argument("--src", default=None, help="只扫描已有 dump 文件(不再碰进程)，等价于 DroidDump 的 --bin")
    ap.add_argument("--max-regions", type=int, default=0, help="winapi 模式：最多 dump 多少个已提交区域(0=不限)")
    ap.add_argument("--live", action="store_true",
                    help="winapi 模式：改为【内存内直接扫】(不落盘)。⚠️ 目标进程易崩/易卡，默认关闭(默认先 dump 到本地)")
    ap.add_argument("--test", default=None, help="先做一次该字符串的定位(ASCII+UTF-16LE)，用于验证读取是否成功")
    return ap.parse_args()


def main():
    args = _parse_args()
    pid = args.pid_opt if args.pid_opt is not None else args.pid

    print("\n" + "=" * 60)
    print("  进程内存敏感信息扫描器 | 目标 %s | 模式: %s" % (pid, args.mode))
    print("  " + ("纯 WinAPI 自包含(先 dump 到本地再正则)" if args.mode == "winapi" else "frida 注入 agent(降级)"))
    print("=" * 60)

    # 只扫已有 dump
    if args.src:
        scanner = WinapiScanner(0)
        n = scan_file(args.src, scanner)
        print("[*] 扫描文件 %s (%d 字节)" % (args.src, n))
        print_summary(scanner.results, pid)
        if scanner.results:
            p = export_results(scanner.results, pid, args.out)
            if p:
                print("  结果已导出: %s" % p)
        return

    if args.mode == "winapi":
        scanner = WinapiScanner(int(pid), args.out, perm=args.perm)
        try:
            scanner.open_process()
        except PermissionError as e:
            print("[!] %s" % e)
            sys.exit(1)
        if enable_se_debug_privilege():
            print("[*] 已尝试启用 SeDebugPrivilege")

        if args.test:
            hits = scanner.search_string(args.test)
            print("[*] 搜索 '%s': %d 处" % (args.test, len(hits)))
            for h in hits[:10]:
                print("    - %s (%s)" % (h[0], h[1]))
            scanner.close()
            return

        start = time.time()
        if args.live:
            # 内存内直接扫（易崩，默认关闭）
            st = scanner.scan_live(max_regions=args.max_regions)
            name = "live"
        else:
            dump_path = args.dump or os.path.join(os.path.dirname(os.path.abspath(args.out)) or ".", "memdump.bin")
            st = scanner.dump_to_file(dump_path, max_regions=args.max_regions)
            name = dump_path
        scanner.close()
        print("[+] %s 完成! 耗时 %.2f 秒 | 区域 %d | 字节 %.2f MB | 错误 %d | 跳过 %d%s" % (
            "内存内扫描" if args.live else "dump", time.time() - start,
            st["regions"], st["bytes"] / 1024 / 1024, st["errors"], st["skipped"],
            " -> " + dump_path if not args.live else ""))

        if not args.live:
            start = time.time()
            n = scan_file(dump_path, scanner)
            print("[+] 本地正则完成! 耗时 %.2f 秒 | 扫描 %d 字节 | 发现 %d" % (time.time() - start, n, len(scanner.results)))

        print_summary(scanner.results, pid)
        if scanner.results:
            p = export_results(scanner.results, pid, args.out)
            if p:
                print("  结果已导出: %s" % p)
    else:
        scanner = FridaScanner(int(pid), args.out)
        try:
            scanner.attach()
            print("[+] frida 附加成功")
        except Exception as e:
            print("[!] %s" % e)
            sys.exit(1)
        try:
            if args.test:
                hits = scanner.search_string(args.test)
                print("[*] 搜索 '%s': %d 处" % (args.test, len(hits)))
                for h in hits[:10]:
                    print("    - %s (%s)" % (h["address"], h["encoding"]))
            else:
                start = time.time()
                st = scanner.scan()
                print("[+] 扫描完成! 耗时 %.2f 秒 | 发现 %d" % (time.time() - start, len(scanner.results)))
                print_summary(scanner.results, pid)
                if scanner.results:
                    path = export_results(scanner.results, pid, args.out)
                    if path:
                        print("  结果已导出: %s" % path)
        except KeyboardInterrupt:
            print("\n[!] 中断")
        finally:
            scanner.close()


if __name__ == "__main__":
    main()
