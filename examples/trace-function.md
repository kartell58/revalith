# Example: trace and validate one function

Take a function static analysis flagged as suspicious and settle what it
actually does. The goal is a *conclusion*, not more data.

## The starting position

```markdown
Function:   sub_4012a0
Evidence:   references "login_failed" (0x404a10) and "token expired"
            called only from sub_4018c0
            return value branched on by the caller
Hypothesis: participates in authentication failure handling
Confidence: low -- naming is the only evidence so far
```

That is not enough. Here is how to move it to `high`.

## Step 1: confirm the reference statically

```sh
scripts/find-xrefs.py ./app --string "login_failed" --containing-funcs
```

`--containing-funcs` turns the string into a function, which is the
association that made this function interesting. Without it, you have a
string and an address and no link between them.

## Step 2: get an arity estimate

```sh
scripts/function-signatures.py ./app --addr 0x4012a0 --size 0x180
```

Reports which registers are read before written. Arity is usually right
early in a function; the caveat is that a function can read an argument it
does not need, so this is a **lower bound**.

Treat any output as inference. Do not write "the function takes a char* and
an int" because the tool guessed.

## Step 3: read the disassembly

```sh
objdump -d --start-address 0x4012a0 --stop-address 0x401420 \
        --no-show-raw-insn ./app
```

Questions to answer, in order:

1. What happens to each argument before it is used?
2. Which strings are referenced, and under what condition?
3. What other functions are called?
4. Is there a path that returns early?
5. What is in the return register at each exit?

Keep a note of which of these are observations. They are — they are readable
in the listing.

## Step 4: design an experiment that can fail

This is the step most often skipped, and it is the one that matters.

```markdown
Hypothesis: sub_4012a0 runs only on authentication failure.

Test: perform one successful and one failed login, counting executions of
      sub_4012a0 in each.

Outcomes:
  0 calls in success, >0 in failure  -> supports the hypothesis
  >0 in both                          -> refutes it
  0 in both                            -> hypothesis untested (path not taken)
                                       -> the hypothesis is wrong or the
                                          condition was never met
```

The third outcome is the one people forget. "It did not run" does not
confirm "it never runs".

## Step 5: set the breakpoint

```sh
gdb -q ./app
(gdb) b *0x4012a0
(gdb) run
(gdb) info registers x0 x1 x2
(gdb) x/s $x0
(gdb) x/32xb $x1
(gdb) finish
(gdb) info registers x0
```

`finish` is the key command: it runs to the return and shows the return value
without stepping through the whole body.

If the binary is PIE, either run under the debugger (so ASLR is off) or
compute the base from `/proc/<pid>/maps` and break at `base + offset`.

## Step 6: automate the counting

Counting across many runs by hand is error-prone. Use a breakpoint command:

```
(gdb) break *0x4012a0
(gdb) commands 1
  silent
  printf "hit\n"
  continue
  end
(gdb) run
```

Or log arguments without stopping at all:

```
(gdb) commands 1
  silent
  printf "arg0=%s len=%d\n", (char*)$x0, $x1
  continue
  end
```

Then run the success case and the failure case and compare the logs.

## Alternative: Frida

Better when you need many runs, want to avoid the process stopping, or the
target is a library inside a host process.

```javascript
// hook.js
const m = Process.getModuleByName("app");
Interceptor.attach(m.base.add(0x12a0), {
  onEnter(args) {
    this.buf = args[0];
    this.len = args[1].toInt32();
    console.log("enter len=" + this.len + " buf=" +
                hexdump(args[0], { length: Math.min(this.len, 32) }));
  },
  onLeave(retval) {
    console.log("leave ret=" + retval);
  }
});
```

```sh
frida -f ./app -l hook.js --no-pause
```

**The offset must be relative to the module base.** A hardcoded absolute
address will not work with ASLR, and this is the most common Frida error.

## Step 7: read the arguments

Do not assume an argument is a pointer because the disassembly dereferenced
it. Verify:

- is it non-null?
- does it point into a mapped region?
- does the memory look like what you expect?

```javascript
const p = args[0];
const r = Process.findRangeByAddress(p);
console.log("arg0", p, "mapped:", !!r, r ? r.protection : "unmapped");
```

Dereferencing an invalid pointer crashes the target and loses the trace. Check
before reading.

## Step 8: test the negative case

Knowing what happens on failure is only half the evidence. Send malformed
input and observe.

```markdown
Test: 4 inputs to the same parser path
  1. valid header          -> returns 16, caller takes the success branch
  2. length field 0        -> returns 0, caller takes the error branch
  3. length field absurd   -> returns 0, no out-of-bounds read observed
  4. truncated buffer      -> returns 0
```

The malformed cases matter as much as the valid one, because they distinguish
a parser from a function that merely happens to read a length.

## Step 9: raise confidence honestly

```markdown
## Finding

Function: sub_4012a0

Hypothesis: parses a message header and returns the payload offset.

Evidence:
  - reads u16 at offset 0, u32 length at offset 2 (disassembly 0x4012b4,
    0x4012c0)
  - caller passes a buffer plus a length (traced, all observed calls)
  - return value is used as a payload offset by the caller (0x4018e4)
  - executed only on authentication failure: 0 calls across 5 successful
    logins, 3 calls across 5 failed logins
  - returns 0 for zero and oversized length fields (tested)

Conclusion: parses the header and returns the payload offset.
            Confidence: high.

Notes: the field at offset 6 is read but its purpose is unexplained; it does
      not change the returned value in any tested case.
```

The residual uncertainty is stated, not buried. "Does not change the returned
value in any tested case" is precise and useful; "unknown" alone is not.

## Step 10: record reproducibility

```markdown
Reproduce:
  binary : sha256:9f2c...
  host   : Linux 6.x aarch64
  tools  : gdb 13.1, frida 16.1
  setup  : base from /proc/<pid>/maps, breakpoint base+0x12a0
  test   : 5 successful + 5 failed logins against the same account
  result : counts as recorded above
```

Anyone else can rerun this and get the same numbers, or discover that the
result does not reproduce — which is itself worth knowing.