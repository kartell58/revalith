# Example: investigate a web target

A worked example: from "we have a URL" to a specific, tested conclusion.

> All target data below is **synthetic**, invented for this example to show
> the shape of a good investigation. Every command is real and runnable;
> substitute your own target.

## The question

> A user reports the app works but the website is broken for the same account.
> We need to know whether this is a client/server difference we can work
> around, or a server-side regression.

That question decides the tools. This is not a case for a decompiler; it is a
case for capturing requests and diffing them.

## Step 1 — passive baseline

```sh
scripts/web-enum.py https://app.example.com --json > baseline.json
```

```
target     : https://app.example.com
mode       : passive
  status        : 200
  final url     : https://app.example.com/
  headers:
    server: nginx/1.24.0
    x-powered-by: Express
    content-security-policy: default-src 'self'
    set-cookie: session=…; HttpOnly; Secure; SameSite=Lax
```

**Observed**, not concluded:

- `Server: nginx/1.24.0` — a self-declared header.
- `X-Powered-By: Express` — a self-declaration, and Express disables it by
  default, so someone re-enabled it.
- CSP present with `default-src 'self'`.
- Session cookie carries HttpOnly, Secure, SameSite=Lax.

Nothing here is a finding yet. It is what the server sent.

## Step 2 — the technology question, answered honestly

```
nginx  [server]  evidence=self_declaration  confidence=medium
    header server: nginx/1.24.0
    caveat : Server header is set by the operator and can be spoofed or
             replaced by a CDN.

Express  [framework]  evidence=self_declaration  confidence=medium
    header x-powered-by: Express
```

Both are `medium`, and the reason is the same: a header the operator chose to
send. If we need to know what actually terminates the connection, the test is
infrastructure-level — the IP's reverse DNS, and whether a CDN is in front.

**Do not write** "the application runs on nginx and Express" as a conclusion.
Write "the server self-reports nginx and Express; neither has been
independently confirmed."

## Step 3 — find the failing request

Reproduce the failure and capture it. A browser export (HAR) is the simplest
route; DevTools → Network → the failing request → "Copy as cURL" also works
and can be converted.

Save both sides as JSON:

```json
// working.json — from the app
{"method":"GET",
 "url":"https://app.example.com/api/v2/session",
 "headers":{"Host":"app.example.com",
            "Accept":"application/json",
            "Authorization":"Bearer eyJhbGciOi…",
            "X-Client-Version":"4.2.0"},
 "body":null}
```

```json
// failing.json — from the browser, same endpoint
{"method":"GET",
 "url":"https://app.example.com/api/v2/session",
 "headers":{"Host":"app.example.com",
            "Accept":"text/html,application/xhtml+xml,…",
            "Cookie":"session=…"},
 "body":null}
```

## Step 4 — diff

```sh
scripts/web-enum.py x --compare working.json failing.json
```

```
differences observed: 5

1. header:accept
     working client : 'application/json'
     failing client : 'text/html,application/xhtml+xml,…'
2. header:authorization
     working client : 'Bearer ...<96 chars redacted>'
     failing client : None
     only present in the working client
3. header:cookie
     working client : None
     failing client : 'session=…; HttpOnly; Secure'
     only present in the failing client
4. header:x-client-version
     working client : '4.2.0'
     failing client : None
5. header:user-agent
     working client : 'ExampleApp/4.2.0 (Android 14)'
     failing client : 'Mozilla/5.0 … Chrome/120'

signal headers involved: accept, authorization, cookie, user-agent
```

Five differences. The token was redacted before it reached the output, which
matters because these files get pasted into issues.

## Step 5 — hypotheses, each with a test

Now the reasoning. Write every candidate, then kill them in order of
cheapness:

```markdown
H1: The endpoint requires Accept: application/json.
H2: The endpoint requires the Authorization header.
H3: The endpoint rejects requests without a session cookie.
H4: The endpoint requires X-Client-Version.
```

`User-Agent` is **not** on the list, and that omission is deliberate. It is the
difference everyone reaches for first, and it is the one most likely to be a
coincidence. Test it last, and only if the others are exhausted.

## Step 6 — controlled reproduction, one variable at a time

Start from the working request, which is known to succeed:

```sh
BASE='https://app.example.com/api/v2/session'
AUTH='Authorization: Bearer eyJhbGciOi…'

probe() { curl -sS -o /tmp/body -w '%{http_code}' "$@"; }

echo -n "baseline (as captured)        : "
probe -H 'Accept: application/json' -H "$AUTH" -H 'X-Client-Version: 4.2.0' "$BASE"; echo

echo -n "Accept: text/html             : "
probe -H 'Accept: text/html' -H "$AUTH" -H 'X-Client-Version: 4.2.0' "$BASE"; echo

echo -n "no Authorization             : "
probe -H 'Accept: application/json' -H 'X-Client-Version: 4.2.0' "$BASE"; echo

echo -n "no X-Client-Version          : "
probe -H 'Accept: application/json' -H "$AUTH" "$BASE"; echo

echo -n "browser UA                   : "
probe -H 'Accept: application/json' -H "$AUTH" -H 'X-Client-Version: 4.2.0' \
      -H 'User-Agent: Mozilla/5.0 Chrome/120' "$BASE"; echo
```

*(Illustrative results — run these against your own target.)*

```
baseline (as captured)        : 200
Accept: text/html             : 403
no Authorization             : 401
no X-Client-Version          : 200
browser UA                   : 200
```

Three results in one run, and note what the last line means: **the browser
User-Agent is not the cause.** It was tested and eliminated. Had we started
there and seen the 403 disappear, we would have recorded a confident and
entirely wrong explanation.

## Step 7 — conclusion

```markdown
## Finding

Symptom:  the app reaches /api/v2/session; the same request from a browser
          returns 403 with an HTML body.

Hypothesis: the endpoint requires Accept: application/json.

Evidence:
  - replaying the captured request with Accept: text/html returns 403
  - restoring Accept: application/json returns 200
  - repeated 5 times with identical results
  - varying User-Agent alone does not change the outcome (200 either way)

Ruled out at the same time:
  - X-Client-Version: not required (200 without it)
  - User-Agent: not the cause (200 with the browser's UA)

Confidence: high — isolated to a single variable and reproduced.

Remaining: the 401 without Authorization is expected and untested further;
     whether the 403 body contains a server error ID was not examined.
```

The "ruled out" section is what makes this reusable. The next person does not
re-test the User-Agent.

## Step 8 — record it so it is not re-investigated

If the investigation continues, write the finding into
`project-state/known-protocols.md` or `hypotheses.md` so a later session does
not re-run step 6. See `references/investigation-state.md`.

## Next investigation step

The natural follow-up, and the one to write down before stopping:

- The 403 body was not examined. If it carries a request ID, correlating it
  with server logs would show which check rejected the request — that is the
  direct answer, and it beats further client-side inference.