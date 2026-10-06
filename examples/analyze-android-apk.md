# Example: analyse an Android APK

From an APK to a specific, evidence-backed understanding of what the app does
and how it is packaged.

> Target data is **synthetic**. Commands are real and runnable.

## The question

> We have `app.apk` from an unknown build. Before any code analysis, what is
> this package, what does it request, and what is worth reverse engineering?

## 1. Triage first, not last

```sh
scripts/universal-dump.py ./app.apk -o dump/
```

The dump orients you in seconds and tells you which deep analysis is worth
doing. Reading it first prevents the common failure of starting with the DEX
when the interesting logic is in a stripped native library.

```
type: android-apk   architectures: arm64-v8a, armeabi-v7a, x86_64
```

Three ABIs. That matters: a finding from one is not automatically a finding
from the others, and `dump-diff` will show when they diverge.

## 2. The manifest

```
ANDROID
  kind           : apk
  ABIs           : arm64-v8a, armeabi-v7a, x86_64
  DEX files      : classes.dex, classes2.dex
  native libs    : lib/arm64-v8a/libnative.so
                  lib/armeabi-v7a/libnative.so
                  lib/x86_64/libnative.so
  manifest:
    package        : com.example.app
    version_name   : 2.8.4
    version_code   : 284
    min_sdk        : 24 (Android 7.0)
    target_sdk     : 34 (Android 14)
    debuggable     : False
    cleartext      : True
    permissions    : 11
    activities     : 4
    services       : 2
    receivers      : 1
    providers      : 1
```

Decoded with the bundled binary-XML parser, no `aapt` required. If `aapt` or
`apkanalyzer` exists, the dump also records them in the tools section.

**The two lines that change your plans:**

- `debuggable: False` — no debugger can attach. Every dynamic technique in
  `dynamic-analysis.md` is blocked until that changes. Record it now.
- `cleartext: True` — the app permits HTTP. That does not mean it uses
  plaintext, but it removes an obstacle if it does.

## 3. Permissions are evidence, not conclusions

```
permissions:
  android.permission.INTERNET
  android.permission.ACCESS_NETWORK_STATE
  android.permission.CAMERA
  android.permission.RECORD_AUDIO
  android.permission.READ_EXTERNAL_STORAGE
  android.permission.WRITE_EXTERNAL_STORAGE
  android.permission.ACCESS_FINE_LOCATION
  android.permission.POST_NOTIFICATIONS
  android.permission.FOREGROUND_SERVICE
  com.example.app.permission.MAPS
  androidx.work.impl.background
```

`INTERNET` is a fact. `RECORD_AUDIO` means the app *requested* microphone
access. It does not mean the app records audio — most apps request a broad set
and use a fraction of it.

**Observed:** eleven permissions declared.
**Inferred:** the app may use location; the permission is declared.
**Confidence:** low — until a call site is found.

The custom permissions are the more discriminating data:
`com.example.app.permission.MAPS` is theirs, and `androidx.work.impl.background`
signals WorkManager. Both are stronger signals than the platform permissions.

## 4. Components and exported surface

```
activities : com.example.app.MainActivity
             com.example.app.SettingsActivity
             com.example.app.WebActivity
             com.example.app.DebugActivity
services   : com.example.app.SyncService
             com.example.app.PushService
receivers  : com.example.app.BootReceiver
providers  : com.example.app.DataProvider
```

A `DebugActivity` in a release build is worth a look — not because it is
"exploitable" but because its existence is unexplained.

`BootReceiver` plus `SyncService` suggests background work on device start. That
is a hypothesis with an obvious test: trace the receiver.

Check `exported` on each. Exported components are reachable by other apps,
which makes them interesting for compatibility work and for anyone assessing
the app's attack surface.

## 5. Native libraries

```
binaries
  lib/arm64-v8a/libnative.so
    ELF AArch64 64-bit little-endian, stripped
    size 4128672   stripped=yes   pie=yes
    needs: libc.so, liblog.so, libandroid.so
    JNI exports: 23
    TLS section: no
```

23 JNI exports, and the binary is stripped. JNI exports are the highest-value
thing in this APK: each one is a native function with a name that tells you
the Java method it implements.

```sh
scripts/elf-summary.py dump/extracted/lib/arm64-v8a/libnative.so --symbols exports
```

```sh
nm -D --defined-only dump/extracted/lib/arm64-v8a/libnative.so \
  | grep ' T Java_'
```

```
0000000000009a10 T Java_com_example_app_Media_captureStart
000000000000a240 T Java_com_example_app_Media_captureStop
000000000000a880 T Java_com_example_app_Native_init
000000000000b1c0 T Java_com_example_app_Crypto_decrypt
...
```

`Java_com_example_app_Crypto_decrypt` is a native `decrypt` method on a
`Crypto` class in `com.example.app`. That is a **high-value** lead: there is
Java-side code to read, and the native function has a name.

This is what the JNI naming convention buys you when symbols survive. When
they do not (stripped *and* registration via `RegisterNatives` in
`JNI_OnLoad`), you have to start from the Java side:

```sh
scripts/strings-map.py dump/extracted/classes.dex --search "native " --limit 40
```

Each `native` declaration in the DEX is a method whose body is elsewhere.

## 6. Where does the Java call go?

Map the bridge in both directions:

1. **Java → native**: list `native` declarations in the DEX, get their
   signatures.
2. **Native → Java**: list JNI exports, decode the mangled names back to
   `package.Class.method`.
3. **Reconcile**: an export with no Java declaration means dynamic
   registration; a declaration with no export means a different mechanism.

This is `references/android.md` territory. The point here is that the mapping
turns a stripped 4 MB library into a named API surface.

## 7. Network indicators from the package

```
urls (from assets/config.json):
  https://api.example.com/v2/sync     <- app.apk!assets/config.json  @offset:unknown
  wss://push.example.com/socket        <- app.apk!assets/config.json  @offset:unknown

domains (from libnative.so):
  telemetry.example.net                <- libnative.so  @0x3a1c4
  api.example.com                      <- libnative.so  @0x3a208
```

Two sources, two different evidence qualities. The URLs come from an extracted
config file, so the offset within the original archive is unknown and recorded
as such. The domains come from a raw `.so`, so the offset is exact and
traceable to `objdump`.

Domains in a *native* library are more interesting than domains in a config
file, because a config file can be overridden by the server while a string
compiled into the binary cannot be edited without a rebuild.

## 8. Trace one function to establish behaviour

```sh
gdb -q -p $(adb shell pidof com.example.app | tr -d '\r')
```

If `debuggable: False`, this fails. That is a **blocked** test, and it gets
recorded as blocked rather than retried:

```markdown
### Confirming Crypto.decrypt output format

Status:     blocked (2026-10-06)
Blocker:    debuggable=False; no root available on the test device
What would unblock it: a debuggable build of the same version, or root
```

See `references/investigation-state.md` for why blockers are recorded.

## 9. Document

```markdown
## Analysis: com.example.app 2.8.4

file    : sha256:…  app.apk, versionCode 284
abis    : arm64-v8a, armeabi-v7a, x86_64
manifest: decoded (stdlib binary-XML parser; aapt not required)

Observed:
  - 11 permissions declared, including RECORD_AUDIO and ACCESS_FINE_LOCATION
  - 4 activities, 2 services, 1 receiver, 1 provider
  - WebActivity and DebugActivity present in a release build
  - android:debuggable=false — no debugger can attach
  - usesCleartextTraffic=true
  - libnative.so (AArch64) is stripped, 23 JNI exports
  - JNI export Java_com_example_app_Crypto_decrypt implies a native
    Crypto.decrypt method

Hypothesis: the app performs local decryption using a key obtained from the
            network.

Confidence: low — the JNI name is strong evidence that a decrypt function
exists; the network-key relationship is an untested assumption.

Ruled out: no evidence connects libnative.so to libil2cpp.so; this app does
          not contain libil2cpp.so at all.

Not investigated: WebActivity behaviour; the x86_64 build (assumed but not
                  compared against arm64); broadcast receivers' filters.
```

The "ruled out" and "not investigated" lines are what a colleague needs.

## Next investigation step

- Compare the three ABI builds: `dump-diff.py` on per-ABI extractions will
  show whether `libnative.so` differs in structure, not just in addresses.
- Read `WebActivity` in the DEX. A WebView in a release build with an
  `addJavascriptInterface` call is a bridge worth understanding, and it is
  ordinary compatibility work — you need to know what the page can reach.