# Frida

Runtime instrumentation without recompiling. Hooks by symbol, by module+offset
or by address; works in-process and against spawned processes.

Frida answers questions static analysis cannot: what arguments arrive, what a
function returns, what data actually flows.

## Availability

```sh
frida --version
frida-ps -U          # USB device
frida-ps             # local
```

Requirements: the `frida-server` binary matching the device's architecture and
Frida version must be running on the target, which means root or a
debuggable app on Android. Without it, nothing works — check before planning
around Frida.

## Addresses and ASLR

**Never use a static address directly at runtime.** ASLR and PIE move
everything. Find the module at runtime and add the offset:

```javascript
const mod = Process.getModuleByName("libfoo.so");
const fn = mod.base.add(0x2a4c0);   // static offset 0x2a4c0
Interceptor.attach(fn, { ... });
```

This is the single most common Frida mistake. `Module.getBaseAddress` is the
older API; `Process.getModuleByName(...).base` is current.

On Android, spawn and wait for the module to load, because the library may not
exist at injection time:

```javascript
Java.perform(() => {
  const System = Java.use("java.lang.System");
  System.loadLibrary.overload("string").implementation = function (name) {
    const r = this.loadLibrary(name);
    hookAll();          // now libfoo.so exists
    return r;
  };
});
```

## Hooking a function

```javascript
Interceptor.attach(Module.getBaseAddress("libfoo.so").add(0x2a4c0), {
  onEnter(args) {
    console.log("arg0:", args[0]);
    console.log("arg1:", args[1].toInt32());
    this.self = args[0];      // survive across onLeave
  },
  onLeave(retval) {
    console.log("return:", retval);
    console.log("arg0 was:", this.self);
  }
});
```

`args` exists only in `onEnter`. Save what you need on `this`.

## Reading and writing memory

```javascript
const buf = Memory.readUtf8String(args[0]);
const i   = args[1].readS32();
const u8  = new Uint8Array(args[0].readByteArray(16));
console.log(hexdump(args[0], { length: 32 }));
args[2].writeU32(0x1234);      // modify an argument
```

`readUtf8String` on an arbitrary pointer will crash the target if the pointer
is invalid. Before dereferencing, check plausibility: is it in a mapped
region, is it non-null, does it look like a pointer at all.

## Replacing a function

```javascript
Interceptor.replace(target, new NativeCallback(function (a, b) {
  console.log("called with", a, b);
  return 0x2a;                 // a substitute return value
}, 'int', ['pointer', 'int']));
```

`NativeCallback` types must match the real signature or the ABI breaks — this
is where an inaccurate signature inferred by `function-signatures.py` will
cause a crash. Treat a wrong signature as a hypothesis to verify.

## Hooking by exported name

```javascript
const fn = DebugSymbol.fromName("parse_header");
Interceptor.attach(fn.address, { ... });
```

Only works if the symbol is exported and not stripped. Otherwise use
module + offset, computed from the static binary.

## Listing modules and ranges

```javascript
Process.enumerateModules().forEach(m => {
  console.log(m.name, m.base, m.base.add(m.size));
});
```

`Process.findModuleByName`, `Process.enumerateRanges('rw')` and
`Process.enumerateThreads` help locate heap or stack objects when hunting a
structure.

## Structuring a session

```sh
frida -U -f com.example.app -l hook.js --no-pause
frida -U -n appname -l hook.js
```

`-f` spawns and resumes; `-n` attaches to a running process; `-U` targets a
USB device; `-H host:port` a remote one. `--no-pause` continues automatically
after spawn.

Output goes to stdout. Use `send()` with a Python host for structured results
when the volume is large.

## What Frida can and cannot do

Well suited to: argument and return logging, bypassing checks by replacing
functions, tracing call chains, dumping memory, intercepting libc and Java
methods.

Less suited to: very high call volumes (each hook costs time and can alter
timing), code that self-checks integrity, environments where the server
cannot run.

## Anti-instrumentation

Targets may detect Frida by process name, port scans for the server, or
checking loaded libraries. Counters typically include renaming the agent
(`-n` to set the process name), delaying injection, and hooking the
detection functions themselves. All environment-specific — if it is not
working, say so rather than reporting a failed trace as evidence.

## Safety

Instrumentation runs inside someone else's process. A wrong memory write
corrupts state; a wrong signature crashes it. Start read-only: log first,
change nothing. Only modify values when the experiment requires it, and
record what you modified.