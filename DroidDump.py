# -*- coding: utf-8 -*-
"""DroidDump.py — Android App 内存敏感信息扫描器（复用 PcDump 引擎 + rules.json 规则集）

流程：frida 附加安卓 gadget(zygisk/KsuFrida) ● mem_dump.js 把 r--/rw-/r-x 内存写到设备文件
      ● adb pull 到 PC ● 复用 PcDump 的扫描引擎(ASCII + UTF-16 双对齐) + rules.json 正则扫出
      key/token/新 JS 路径/API 路径/URL。

用法：
  python DroidDump.py --pkg com.example.app --out droid_sens
  python DroidDump.py --pkg com.example.app --host 127.0.0.1:14725
  python DroidDump.py --bin memdump.bin --out droid_sens        # 已 dump 只跑正则
  python DroidDump.py --pkg com.example.app --device usb        # frida USB(frida-server) 而非 gadget
"""
import os, sys, re, time, json, subprocess, argparse, io

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import PcDump   # 复用其 extract_ascii/extract_utf16le/WinapiScanner._scan_bytes/export_results/print_summary

DEFAULT_HOST = "127.0.0.1:14725"
DEFAULT_PKG = "com.example.app"
MEMJS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mem_dump.js")


def sh(*a):
    return subprocess.run(list(a), capture_output=True, text=True, encoding="utf-8", errors="replace")


def run_rules(engine, data, rules):
    """对已 dump 的字节再套 rules.json（新 JS / API 路径等动态面规则）。"""
    off = 0
    CH = 1 << 20
    f = io.BytesIO(data)
    while True:
        blk = f.read(CH)
        if not blk:
            break
        for enc, base_off, unit in (("ASCII", 0, 1), ("UTF16LE", 0, 2), ("UTF16LE", 1, 2)):
            t = PcDump.extract_ascii(blk) if enc == "ASCII" else PcDump.extract_utf16le(blk, base_off)
            if len(t) < 10:
                continue
            for rule in rules:
                try:
                    for m in re.finditer(rule["firstRegex"], t, re.I):
                        val = m.group(0)
                        engine._add(rule.get("name", "RULE"), "", val,
                                    hex(off + base_off + m.start() * unit), enc)
                except re.error:
                    pass
        off += len(blk)


def resolve_pid(dev, a):
    """gadget 端口 ss 解析 → adb pidof → frida 枚举兜底。

    Android 的 comm 只有 15 字符(com.xiaomi.youpin→com.xiaomi.youp)，且 frida-server
    枚举出的 name 常是 App 中文标签(如「小米有品」)而非包名，按包名匹配必落空，
    故优先走 pidof(对截断名/中文名都可靠)，frida 枚举只做最后兜底。"""
    pid = None
    adb = a.adb or "adb"
    if a.device == "gadget" and ":" in a.host:
        port = a.host.rsplit(":", 1)[1]
        r = sh(adb, "shell", "su", "-c", "ss -tlnp | grep %s" % port)
        m = re.search(r"pid=(\d+)", r.stdout)
        pid = int(m.group(1)) if m else None
    if pid is None:
        r = sh(adb, "shell", "pidof", a.pkg)
        m = re.search(r"\d+", r.stdout or "")
        pid = int(m.group(0)) if m else None
    if pid is None and hasattr(dev, "enumerate_processes"):
        procs = dev.enumerate_processes()
        cands = [p for p in procs if a.pkg in p.name or a.pkg.split(".")[-1] in p.name.lower()]
        pid = cands[0].pid if cands else None
    return pid


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pkg", default=DEFAULT_PKG)
    ap.add_argument("--host", default=DEFAULT_HOST, help="gadget 宿主地址(默认 127.0.0.1:14725)")
    ap.add_argument("--device", choices=["gadget", "usb"], default="gadget",
                    help="gadget=adb forward 到宿主端口(默认)；usb=frida USB(frida-server)")
    ap.add_argument("--adb", default=None, help="adb.exe 路径(默认用 PATH 里的 adb)")
    ap.add_argument("--out", default="droid_sens")
    ap.add_argument("--wait", type=int, default=30, help="等 agent dump 完成秒数")
    ap.add_argument("--bin", default=None, help="已 pull 的 memdump.bin 路径(跳过 dump/attach, 只跑正则)")
    ap.add_argument("--rules", default=None, help="规则 JSON(默认同目录 rules.json)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    adb = a.adb or "adb"

    engine = PcDump.WinapiScanner(0)   # 复用其 _scan_bytes(含 ASCII+UTF16 0/1 双对齐) + 去重

    if a.bin:
        data_path = a.bin
        print("[*] 用已有 bin %s" % a.bin)
    else:
        import frida
        if a.device == "gadget":
            host, port = a.host.rsplit(":", 1) if ":" in a.host else (a.host, "")
            subprocess.run([adb, "forward", "tcp:%s" % port, "tcp:%s" % port],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            dev = frida.get_device_manager().add_remote_device(host)
        else:
            dev = frida.get_usb_device()
        pid = resolve_pid(dev, a)
        if not pid:
            print("[X] 找不到目标进程，请确认 app 已启动且 gadget 注入生效/端口正确"); sys.exit(2)

        devfile = "/data/data/%s/files/memdump.bin" % a.pkg
        js = open(MEMJS, encoding="utf-8").read().replace("%%MEMDUMP_PATH%%", devfile)
        print("[*] load mem_dump.js -> 等 %ds dump..." % a.wait, flush=True)
        sess = dev.attach(int(pid))

        def on_msg(m, d):
            pl = m.get("payload")
            if isinstance(pl, str) and pl.startswith("[md]"):
                print("  %s" % pl, flush=True)

        sc = sess.create_script(js)
        sc.on("message", on_msg); sc.load()
        try:
            if a.device == "gadget":
                pass
            else:
                dev.resume(int(pid))
        except Exception:
            pass
        time.sleep(a.wait)
        print("[*] pull 内存文件", flush=True)
        sh(adb, "shell", "su", "-c", "cp %s /sdcard/memdump.bin" % devfile)
        time.sleep(1)
        data_path = os.path.join(a.out, "memdump.bin")
        r = sh(adb, "pull", "/sdcard/memdump.bin", data_path)
        if not os.path.exists(data_path):
            print("[X] pull 失败: %s %s" % (r.stdout, r.stderr)); sys.exit(2)

    data = open(data_path, "rb").read()
    print("[*] pulled %d 字节，开始扫描..." % len(data), flush=True)

    # 1. 复用 PcDump 引擎(URL/关键词/特殊格式)，分块扫
    off = 0; CH = 1 << 20
    with open(data_path, "rb") as f:
        while True:
            blk = f.read(CH)
            if not blk:
                break
            engine._scan_bytes(blk, off)
            off += len(blk)

    # 2. 追加 rules.json 动态面规则(新 JS/API 路径)
    rule_file = a.rules or os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")
    if os.path.exists(rule_file):
        rules = json.load(open(rule_file, encoding="utf-8")).get("rules", [])
        run_rules(engine, data, rules)
        print("[*] 额外套用 %d 条 rules.json 规则" % len(rules))

    PcDump.print_summary(engine.results, a.pkg)
    path = PcDump.export_results(engine.results, a.pkg, os.path.join(a.out, "sensitive_findings.txt"))
    if path:
        print("  结果已导出: %s" % path)
    # frida 的 reactor 线程非 daemon，不显式退出进程会挂住不返回
    try:
        sess.detach()
    except Exception:
        pass
    os._exit(0)


if __name__ == "__main__":
    main()
