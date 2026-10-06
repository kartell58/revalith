# Web Reverse Engineering

Passive-first reconnaissance of web targets, application mapping, and the
"works in the client but not in the browser" investigation.

Web RE earns its own reference because its central mistake is unique: the
temptation to treat a **self-declared header as a fact**. Every other area
in this skill teaches distrust of string naming; here the equivalent trap is
`Server: nginx`.

## The rule for this area

A header is what the server *chose to send*. It is evidence that a string was
sent, and nothing more.

```
Observed:   Server: nginx/1.24.0
Inferred:   The application may be behind nginx.
Confidence: medium
Basis:      self-declared header, trivially spoofable
Test:       resolve the IP, compare against CDN ranges; check for
            CF-Ray or X-Cache-* headers that a CDN would add
```

Contrast with a *structural* indicator, which is harder to fake by accident:

```
Observed:   CF-Ray: 8abc1234-IAD
Inferred:   The response passed through Cloudflare.
Confidence: high
Basis:      CF-Ray is a Cloudflare-specific header; the value also encodes
            a datacenter code (IAD)
```

The bundled tool encodes this distinction: `evidence_kind` is either
`structural` or `self_declaration`, and self-declarations always ship with a
`caveat`.

## Passive vs active

Keep these separate in your notes. A reader must be able to tell what was
*learned* from what was *asked*.

| Passive | Active |
| --- | --- |
| DNS resolution | TLS certificate retrieval (opens a connection) |
| HTTP headers of a normal GET | Redirect following |
| `robots.txt`, `sitemap.xml` | Directory/endpoint probing |
| JavaScript served to any visitor | Header or method variation |
| Certificate transparency lookups | WebSocket handshake attempts |

Passive work reads what the target publishes to anyone. Active work is
interaction, and it is logged. `web-enum.py` defaults to passive and records
every request in a network activity log; `--active` and `--tls` opt in.

```sh
scripts/web-enum.py https://target.example                 # passive
scripts/web-enum.py https://target.example --tls --active  # interaction
```

## Reconnaissance, in order

```sh
scripts/web-enum.py https://target.example --dns --tls -o report.json
```

The tool fetches, in order: DNS (opt-in), the TLS certificate (opt-in), the
main document, `robots.txt`, `sitemap.xml`, then referenced JavaScript
(opt-in). Each step is independent; a failure in one is reported and the
others continue.

## Technology identification

`web-enum.py` reports a technology only with the evidence attached:

```
nginx  [server]  evidence=self_declaration  confidence=medium
    header server: nginx/1.24.0
    claim  : nginx is likely present. This is a self-declared header, not
             proof of the origin server.
    caveat : Server header is set by the operator and can be spoofed or
             replaced by a CDN.
```

Coverage: nginx, Apache, IIS, Caddy, OpenResty, LiteSpeed, Envoy, Cloudflare,
Akamai, Fastly, Varnish; PHP, ASP.NET, Node.js, Express, Django, Laravel,
Spring, Rails, Gunicorn, Tomcat, Jetty; WordPress, Drupal, Joomla, React,
Angular, Vue, GraphQL in body content.

Weak fingerprints are deliberately marked `low` and carry a caveat naming the
ambiguity. `react` and `vue` markers in particular are not conclusive, and the
tool says so rather than implying a framework was identified.

## Application mapping

Map what the site actually exposes, and record it as observed:

| Surface | Where to look |
| --- | --- |
| Routes and paths | JavaScript strings, `href`/`src` in HTML, sitemap |
| API endpoints | `JS_PATH` matches: `/api/*`, `/v1/*`, `/graphql`, `/rpc` |
| WebSocket URLs | `wss://` / `ws://` in bundles and inline scripts |
| GraphQL | `/graphql` path or `graphql` in client config |
| Feature flags | SCREAMING_CASE identifiers in bundles |
| Hosts referenced | domain-shaped strings in bundles |
| Source maps | `sourceMappingURL=` comments |
| Public config | `.json`, `.js` config objects, `config` endpoints |

```sh
scripts/web-enum.py https://target.example --js --json > web.json
```

Everything extracted from JavaScript is **a string in a file**. An endpoint
named in a bundle is not thereby reachable, current, or intended for
third-party use. The tool's output carries this caveat in the `note` field of
every JS section.

Source maps deserve attention: `//# sourceMappingURL=app.js.map` in a
production bundle, and the map being served, will often give you readable
original source. That is often the fastest path from a minified bundle to
real logic.

## Client vs browser behaviour

The scenario: **an app or custom client reaches the API; a browser does not.**

The first instinct is to blame a `User-Agent` filter. Resist it. A request
that fails is a puzzle in the *difference* between the two requests, and the
User-Agent is one of many candidate differences.

### The workflow

```
working client
      ↓  capture
browser request
      ↓  normalise
diff
      ↓  identify meaningful differences
hypothesis
      ↓  controlled reproduction
confirmation / refutation
```

### Capture both

Whatever your capture format, produce two request records with the same
fields. `web-enum.py --compare` reads JSON shaped like:

```json
{"method": "GET",
 "url": "https://api.example.com/v1/profile",
 "headers": {"User-Agent": "...", "Authorization": "..."},
 "body": null}
```

A HAR file works too — pass the entry, and the `request` object is used.

### Diff

```sh
scripts/web-enum.py x --compare working.json failing.json
```

The tool compares a fixed field set: method, URL, path, query, HTTP version,
every `header:*` of interest, body, body hash, TLS, and the WebSocket
handshake. It reports every difference with a one-line description, and
separately lists which *signal* headers differ — those are the ones most
often load-bearing.

Credentials are redacted in the output. An `Authorization` or `Cookie` value
is replaced before it can reach a shared report.

### Read the differences as candidates, not conclusions

The diff gives you observed differences. It does not tell you which one
caused the failure, and the tool says so explicitly. A `User-Agent`
difference is one candidate among the differences; treating it as the answer
without a test is the exact failure this skill exists to prevent.

### Controlled reproduction

For each candidate difference, change **one** thing at a time:

1. Replay the working request unchanged. Confirm it still succeeds. If not,
   the behaviour is not deterministic, or the token expired — establish that
   before testing anything else.
2. Add the failing client's `User-Agent` to the working request. If it still
   succeeds, `User-Agent` is not the cause. Record that.
3. Remove `Authorization`. If it now fails, the endpoint requires it.
4. Change `Accept` from `application/json` to `text/html`. Many APIs route on
   `Accept` and return HTML error pages for non-JSON requests.
5. Remove `Origin`/`Referer`. Some gateways apply CORS or CSRF checks only
   when those headers are present.
6. Change `Sec-Fetch-*`. A server can branch on these to distinguish a
   browser from a client, and they are trivially absent from many HTTP
   libraries.

Order matters: cheap, unambiguous ones first (`Accept`, `Content-Type`,
`Authorization`). `User-Agent` last, because it is the most likely to be a red
herring.

### Write a minimal reproducer

When the cause is found, capture it as a small, runnable client. This converts
a one-off observation into a repeatable test:

```python
import json, urllib.request, urllib.error

def call(url, headers, body=None, method="GET"):
    req = urllib.request.Request(url, method=method, data=body,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return {"status": r.status, "body": r.read(4096)}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read(4096)}

HEADERS = {
    "Accept": "application/json",
    "Authorization": "Bearer <token>",
}

print(call("https://api.example.com/v1/profile", HEADERS))
```

`curl` works equally well when the difference is a header:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer <token>' \
  https://api.example.com/v1/profile
```

Keep the reproducer minimal and the token out of version control. A
reproducer that reproduces reliably is worth more than a long explanation of
how the request worked.

## Documenting

```markdown
## Finding

Symptom:     the app's API calls succeed; the same calls from a browser
             return 403 with an HTML body.

Observed differences (browser vs app):
  - Accept: text/html vs application/json
  - Authorization: absent vs present
  - Origin: absent vs https://app.example.com
  - User-Agent: differs

Test:        replayed the app request with Accept: text/html
             -> 403, HTML body. Restored Accept -> 200.
             Repeated 5 times.

Conclusion:  the endpoint requires Accept: application/json; with
             text/html it returns an HTML 403. Origin and User-Agent were
             tested separately and neither changed the result.
Confidence:  high -- isolated to one variable and reproduced.
```

The lines "Origin and User-Agent were tested separately and neither changed
the result" are what make this a finding. They also record which plausible
explanations were eliminated, so nobody repeats them.

## Scope

`web-enum.py` inspects only the hosts you name. It does not crawl, brute-force
paths, fuzz parameters, or attempt authentication. Those are outside what this
tooling does, and outside the scope this skill documents. Use it against
systems you own or are authorised to assess.

## See also

- `tooling.md` — probing which HTTP and cert tools exist
- `binary-diff.md` — the binary vs semantic difference distinction, applied
  when comparing two builds of a web client's native components
- `investigation-state.md` — recording dead ends so a failed hypothesis is not
  retried