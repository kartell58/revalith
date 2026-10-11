# Emulation

Emulation is what makes dynamic analysis possible when the target cannot run
here. Wrong architecture, no device, no hardware, a hostile environment, or a
program that only runs for ten seconds on the hardware it came from.

It is also the easiest place in this skill to produce a confident wrong
answer, because an emulator is a *model* of a machine and every model answers
some questions and silently mis-answers others. Most of this file is about
knowing which.

## When it is the right tool

| Situation | Why emulation |
| --- | --- |
| Target architecture is not the host's | `qemu-user` runs it anyway |
| Firmware or bare-metal image | nothing on the host will run it |
| Hardware is unavailable or the target is gone | a description of it is enough to run |
| Target is hardened against debuggers | no debugger is attached |
| Anti-debugging checks timing | the emulator's timing is under your control |
| Running on a device risks the device | sandbox |

And when it is not, despite being tempting:

- **Native execution exists and you have it.** Use it. Emulation adds a
  translation layer between the question and the answer, and it is
  substantially slower.
- **The question is about a peripheral.** No user-mode emulator models a real
  DMA controller. See `firmware.md`.
- **You need cycle-accurate timing.** Emulated timing is not a model of the
  target's; it is a model of the emulator's.

## Choosing a level

Pick the cheapest level that can answer the question. Each step up costs
fidelity you may not be able to buy back.

| Level | Tool | Answers | Does not answer |
| --- | --- | --- | --- |
| Instruction-level | Unicorn | what does this function do, given these inputs | anything about the surrounding system |
| User-mode | `qemu-user` | behaviour of a whole process | syscalls the target makes that the host lacks; timing |
| Full-system | `qemu-system` | boot, firmware, kernels, whole machines | peripheral timing; anything faster than real time |
| Library emulation | reimplement the imports | behaviour of one function without running the binary | whether the real library agrees with your model |

Most investigations need the first two. The third is what firmware work needs.

## qemu-user

```sh
qemu-aarch64 -L /usr/aarch64-linux-gnu ./libfoo.so
qemu-arm-static ./rom.bin
```

`-L` points at the target's library directory. Without it, dynamic binaries
fail at the loader, and the error ("No such file or directory" for a file that
exists) is the host's filesystem being mistaken for the target's.

Useful flags, in the order they usually matter:

| Flag | Why |
| --- | --- |
| `-strace` | every syscall, with arguments — the cheapest behaviour characterisation available |
| `-g <port>` | open a GDB server, then attach from the host |
| `-d in_asm,cpu` | log translated blocks; use sparingly, it is enormous |
| `-singlestep` | one instruction at a time, for a precise first fault |
| `-one-insn-per-tb` | translation-block granularity, when stepping behaves oddly |

```sh
qemu-aarch64 -g 1234 ./target &
gdb -q
(gdb) set architecture aarch64
(gdb) target remote :1234
(gdb) info registers pc x0 x1
```

Attaching a debugger to an emulator is the normal way to get register-level
observation on a foreign architecture. `gdb.md` covers the rest.

`qemu-user` is not transparent. It translates syscalls and sometimes
reinterprets them, and it has historically handled some of them incorrectly
for edge cases. A syscall behaving differently under emulation is a finding
about the emulator unless you have evidence otherwise.

## Instruction-level: Unicorn

When the question is "what does this function do given these arguments" and
nothing else matters, emulating the whole process is overkill.

The shape is always the same, and it is a *harness* you write, not a tool you
point at a binary:

```
1. Map memory:  stack, heap, the module's segments, anything it will read
2. Write inputs into that memory
3. Set the registers per the calling convention
4. Emulate N instructions, or until a stop condition
5. Read outputs back out
6. Record what you mapped, what you set, and where you stopped
```

What you must be careful about:

- **Stop conditions.** Stopping on a fixed instruction count gives a result
  that depends on the emulator, not on the function. Stop at a return
  address, a branch into an unmapped page, or an explicit hook.
- **Uninitialised memory reads.** A harness that maps zeroed memory will make
  an uninitialised read look like a zero. That is a bug you introduced, and it
  will look exactly like a finding.
- **Missing imports.** If the function calls something you did not hook, the
  result is whatever the harness did. Hook every call the function makes on
  the paths you care about, and say which ones you hooked.
- **Calls out are not calls into.** If the target function calls the outside
  world, you have not emulated the target — you have emulated a fragment.

What it is genuinely good for: brute-forcing an input space, checking a
hypothesis about a single routine's arithmetic, and confirming a model before
writing it in C.

## Full-system

For firmware, kernels, and anything with a bootloader. You supply the machine:
memory layout, CPU, devices, and the disk image.

```sh
qemu-system-aarch64 -M virt -nographic -kernel image.bin \
    -drive file=rootfs.img,format=raw,if=none,id=hd -device virtio-blk-device,drive=hd
```

Two things to establish before trusting any of it:

1. **Where execution starts.** A reset vector, a bootloader, a ROM header —
   get this from the image, not from the filename. `firmware.md` covers it.
2. **What the machine description assumes.** `-M virt` is a *particular* board.
   Code that depends on a peripheral it does not have takes a path that the
   real board would not. That divergence is invisible unless you look for it.

Full-system emulation is where firmware reverse engineering becomes possible
at all, and it is also where the most time is lost to a device model that does
not match the hardware. Confirm the boot reaches your code before treating a
silent failure as a finding about the target.

## Determinism under emulation

Emulation is deterministic in a way hardware is not, which makes it *good* for
differential testing and dangerous for conclusions about timing.

- The same emulated machine with the same image produces the same execution,
  run after run. Host scheduling does not reach the guest.
- Guest reads of the clock return whatever the model returns. Depending on the
  model that may be real time — in which case your "deterministic" runs are not.
- Emulated timing is *slow*, and a program that reads a clock to measure
  something will measure the emulator, not the target.

Before comparing an emulated original against an emulated reimplementation,
establish determinism with `determinism-check.py`. If the emulated original
itself varies run to run, the cause is in the harness or the model, not in
either implementation.

## What emulation does not prove

This is the part that matters, and it is the part most often skipped.

| Claim | Emulation gives you | It does not give you |
| --- | --- | --- |
| "this function adds the two values" | the register result | that the real build's compiler produced the same addition |
| "this code path runs on real hardware" | that it runs under this model | that the hardware reaches it |
| "it takes 3 ms" | that the emulator took 3 ms | the real duration |
| "no device is required" | that the model lacks it | that the real hardware lacks it |
| "it does not use this peripheral" | that the model does not present it | that the firmware cannot touch it |

Two conclusions are worth stating outright:

**An emulated crash may be the emulator.** If your harness is wrong, the fault
you are chasing is yours. Confirm a fault reproduces on native execution, or
that it does not depend on the harness, before treating it as a finding about
the target.

**A path that never executes under emulation may execute on hardware.** The
emulator omits devices, has different timing, and answers uninitialised memory
differently. "Never observed" is a statement about the emulator.

## Anti-emulation checks

Targets notice emulators, and the checks are cheap:

| Check | Looks at | Note |
| --- | --- | --- |
| CPUID | hypervisor bit, vendor strings | an answer the model must get right |
| timing | rdtsc, `clock_gettime` deltas | emulated timing is much slower |
| device enumeration | a device the real board has, absent here | the model, not the target |
| `/proc/cpuinfo`, DMI strings | "QEMU", "VirtualBox", generic values | plain text |
| file and path layout | `/sys/class/dmi`, `/proc/scsi` | same |
| timing of an empty loop | a calibration loop | same as timing |

Seeing one of these is a finding about the *target*: it checks its
environment, which means the check matters to it. Record it with the evidence
and move on to a different question — a dump of the unpacked image, or analysis
on real hardware — rather than escalating into a patching project.

Note the discipline this skill already uses elsewhere: a check for a known
string is evidence that the string is compared; it is not yet evidence of what
happens when the comparison passes. That needs a test.

## Recording an emulated run

The record below is illustrative — the fields are what to capture, the values
are an example rather than a measurement.

```markdown
Test:        executed the authentication path under qemu-user
Binary:      sha256:9f2c...  libfoo.so 0.4.1 aarch64
Emulation:   qemu-aarch64 (version as installed), -L /usr/aarch64-linux-gnu
Machine:     user-mode; no peripheral model
Setup:       gdb remote :1234, breakpoint at base+0x1230
Conditions:  input file fixture; seed fixed; clock not stubbed
Observed:    called once; arg0 = "login_failed"; return 1
Conclusion:  participates in login failure handling. Confidence: high
Limitation:  timing-dependent branches are not exercised under emulation
```

The `Emulation` and `Machine` lines are the ones that matter later. A finding
recorded without them cannot be told apart from one made on real hardware.

## Recording an instruction-level harness

Also illustrative. The `Hooks` and `Stop` lines decide whether the result
means anything at all.

```markdown
Test:        emulated 0x401230 standalone
Mapped:      stack 0x7000-0x8000, module at 0x400000, heap 0x100000
Registers:   x0 = 0x8000 (arg), x1 = 0x100 (len), pc = 0x400000
Hooks:       malloc -> fixed 0x200000; free -> no-op; strlen -> emulated
Stop:        return to 0x400010, or 100k instructions, whichever first
Result:      x0 = 0x23, memory at 0x8000 unchanged
Limitation:  calls outside the hooks are not emulated; a path through one
             would produce the harness's behaviour, not the target's
```

The `Hooks` and `Stop` lines decide whether the result means anything. Without
them, a reader cannot tell an observation from an artefact of the harness.

## See also

- `dynamic-analysis.md` — when to leave static analysis at all
- `firmware.md` — the targets that most need emulation, and how to read one
- `gdb.md`, `lldb.md` — attaching once the emulator is listening
- `memory-runtime.md` — regions, address spaces and provenance in a live map
- `obfuscation.md` — when the code is unreadable because it was made so
- `reconstruction.md` — emulated observations are evidence like any other