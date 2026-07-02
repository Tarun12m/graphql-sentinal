# GraphQL Sentinel

A focused GraphQL security-testing extension for [Burp Suite](https://portswigger.net/burp), built
on the **Montoya API** in Java. Burp's native GraphQL support is thin — Sentinel adds a purpose-built
toolkit for the areas generic tooling handles poorly: **field-level authorization**, **query
depth/complexity (DoS)**, and **request batching**. Conservative, scope-respecting defaults throughout.

> ⚠️ **Authorized use only.** Use it only against systems you own or are explicitly permitted to test
> (e.g. a scoped engagement or an intentionally vulnerable lab such as
> [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application)). Testing without
> authorization is illegal in most jurisdictions.

## Modules & findings

| Module | Phase | What it does | Severity |
| --- | --- | --- | --- |
| **Detection + scope gate** | Passive | Finds GraphQL endpoints (path, content-type, body/response shape). Never acts on out-of-scope hosts. | INFO |
| **Introspection** | Passive/Active | Detects if introspection is enabled; parses the schema into a readable tree. Degrades gracefully when disabled. | INFO |
| **Field authorization** *(core)* | Active | Replays observed privileged queries as a low-priv user and unauthenticated, then diffs responses to flag fields a lower principal can read but shouldn't. | HIGH/MEDIUM |
| **Depth / complexity** | Active | Sends one hard-capped, deeply-nested query to prove a missing depth/cost limit — without trying to exhaust the server. | MEDIUM |
| **Batching** | Active | Sends one tiny benign batch to detect whether array batching is accepted (can undermine rate limiting). | MEDIUM |
| **Injection surface** | Passive | Flags arguments whose names suggest injection sinks (SQL, path, SSRF, command) for **manual** review. Never sends payloads. | INFO |

Findings carry severity, description, affected operation, endpoint, remediation, and full
request/response evidence, and export to **JSON** or a self-contained **HTML** report.

## Build & install

Requires JDK 17+ and Burp 2023.x+ (internet needed on first build for the Montoya API and Gson).

```bash
./gradlew build          # → build/libs/graphql-sentinel-1.0.0.jar
```

**Load the extension in Burp:**

1. Open Burp → **Extensions** tab → **Installed** sub-tab.
2. Click **Add**.
3. Set **Extension type** to **Java**.
4. Under **Select file**, browse to `build/libs/graphql-sentinel-1.0.0.jar`.
5. Click **Next** — the output log should show it loaded with no errors.
6. Click **Close**. A new **GraphQL Sentinel** tab appears in Burp's top menu.

To update after a rebuild: select the extension in the list and click **Reload** (or untick/tick it).

Gson is shaded into the jar; the Montoya API is `compileOnly` — provided by Burp at runtime.

## Usage (against DVGA)

```bash
docker run -t --rm -p 5013:5013 -e WEB_HOST=0.0.0.0 dolevf/dvga   # endpoint: /graphql
```

1. Add the target to Burp's **Target → Scope**.
2. Browse the app through Burp **as the privileged user** — detected endpoints appear on the *Endpoints* tab.
3. Run **Introspection** (needed before Depth, which reuses the schema).
4. On *Configuration*, enter a **low-privilege** session and **ARM** active testing (disarmed by default).
5. Select the endpoint and run **Field Authorization**, **Depth**, **Batching**.
6. Review results on *Findings* and export JSON/HTML.

> Detection only ingests **proxy** traffic (not Repeater/Scanner). Active tests require arming and an
> in-scope host. If Field Authorization finds nothing, check you browsed as the privileged user first.

## Design highlights

**Why field authorization is the core.** Missing object/field-level authorization is the most common
high-impact GraphQL bug and the one scanners handle worst, because it's invisible without a notion of
*who should see what*. Everything else exists to feed it good input.

**How false positives are minimised** (logic isolated in the Burp-free, unit-tested `AuthzComparator`):
only the auth material is swapped so any response difference is attributable to identity; HTTP 401/403
or a GraphQL auth error counts as a *working* control (no finding); comparison is per top-level field
so the exact leaking field is named; identical values are HIGH (direct leak) while different non-null
values are MEDIUM (reachable, confirm manually); findings de-duplicate per operation.

**Why depth/batching is bounded.** The goal is to *demonstrate a missing control, not cause an outage*.
Depth sends one query capped at 15 levels (default 8); batching sends one benign 3-op batch. Neither
module has a code path that ramps up or brute-forces.

## Safety defaults

| Control | Default |
| --- | --- |
| Respect Burp scope | Always on, fails closed |
| Active testing | **Disarmed** until armed in the UI |
| Max query depth | 8 (hard cap 15) |
| Max batch size | 3 (hard cap 5) |
| Replay mutations | **Off** |
| Injection testing | Flag only, never exploit |

## Project layout

```
com.gqlsentinel
├── core/      # scope gate, detector, parser, request builder/sender, config, passive handler
├── model/     # Finding, Severity, SessionProfile, DetectedEndpoint, GraphQLSchema, stores
├── modules/   # 6 engines + AuthzComparator + DepthQueryGenerator + registry
├── ui/        # Swing suite tab: Findings, Endpoints, Config, Schema, About
└── export/    # JsonExporter, HtmlExporter
```

Passive detection is always on and never sends traffic; the only egress path is `ActiveRequestSender`,
which enforces the scope/arm gate, so no module can send an ungated request.

## Testing

```bash
./gradlew test
```

Covers the two logic-heavy, Burp-independent classes: `AuthzComparator` (the false-positive-sensitive
diff) and `DepthQueryGenerator` (self-reference discovery + bounded query generation).

## License

MIT — see [LICENSE](LICENSE). Provided for authorized security testing and education only; the author
accepts no liability for misuse.
