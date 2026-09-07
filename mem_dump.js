// mem_dump.js — Android 进程内存 dump：把 r--/rw-/r-x 可读内存按页写到设备文件。
// 由 DroidDump.py 加载；%%MEMDUMP_PATH%% 会在运行时替换为目标路径。
'use strict';
var FN = null;
var CAP = 0x30000000;          // 768MB 上限(覆盖 app 大部分内存)
var OUT = '%%MEMDUMP_PATH%%';
function dump(){
  if (FN) return; FN = true;
  try{
    var ranges = [], seen = {};
    var lists = [Process.enumerateRanges('r--'), Process.enumerateRanges('rw-'), Process.enumerateRanges('r-x')];
    lists.forEach(function(list){
      list.forEach(function(r){ if(!seen[r.base.toString()]){ seen[r.base.toString()]=1; ranges.push(r); } });
    });
    send('[md] readable ranges=' + ranges.length);
    var out = new File(OUT, 'wb');
    var total=0, nrange=0;
    ranges.forEach(function(r){
      if (total >= CAP) return;
      if (r.size < 64 || r.size > 0x10000000) return;
      nrange++;
      var off = 0;
      while (off < r.size && total < CAP){
        var chunk = Math.min(65536, r.size - off);
        try{
          var u = new Uint8Array(Memory.readByteArray(r.base.add(off), chunk));
          out.write(u); total += chunk; off += chunk;
        }catch(e){ off += 65536; }
      }
    });
    out.flush(); out.close();
    send('[md] DONE ranges=' + nrange + ' total=' + total);
  }catch(e){ send('[md] err ' + e); }
}
setTimeout(dump, 8000);
setTimeout(dump, 20000);
send('[md] mem_dump armed');
