# Aletheia Lite — Authorization Kernel Security Audit (L1–L7)

Scope: `core/pipeline.py`, `core/trifecta.py`, `core/scout.py`, `core/nitpicker.py`,
`core/judge.py`, `core/receipts.py`, `core/manifest.py`, `core/tpm.py`,
`core/canonicalization.py`, `core/sanitize.py`, `core/text_normalization.py`,
`core/symbolic_narrowing.py`, `core/sandbox.py`, `core/audit.py`, `core/decisions.py`,
`core/config.py`, `core/__main__.py`, `core/demo.py`, `guards/*`, `detectors/*`,
`dashboard/server.py`, `core/rate_limit.py`.

All line numbers refer to the reviewed revision on this branch.

---

## L1 / L3 — Authorization pipeline & Zero-Standing-Privilege / confused-deputy findings

### Finding 1 — `declared_resources` defaults to the request's own `resources`, nullifying ZSP (CRITICAL)

- **Location**: `core/pipeline.py:162` — `declared = request.metadata.get("declared_resources", request.resources)`.
- **Mechanism**: `ZeroStandingPrivileges.enforce()` (`guards/zero_standing_privileges.py:69`) denies a resource when `res not in declared_set`. ZSP's entire value proposition is that *declaration* is independent of the *request* — an agent must pre-commit to a scope before it knows it will be granted. Here, if the caller simply omits `declared_resources` from metadata, `declared` is set equal to `request.resources`, so `res not in declared_set` can never be true. The "undeclared resource" branch of ZSP is dead code for any caller that doesn't opt in to sending `declared_resources`.
- **Conditions**: any `submit()`/`process()` call that supplies `resources=[...]` without `metadata={"declared_resources": [...]}`. This is the *unmarked default* — nothing forces a caller to populate `declared_resources`, and the CLI (`core/__main__.py:48-49`) only sets it when `--declare` is explicitly passed.
- **Impact**: ZSP degrades to a plain grant-pattern check (`declared vs. allowed`), losing the "no ambient/undeclared reach" property entirely. A compromised or careless agent wrapper that requests exactly what it wants, whether or not that was pre-registered, sails through.
- **Fix**: `declared_resources` must come from a source the requester cannot control at request time — e.g. a capability/session registration step (agent registers its intended scope before the task starts; the pipeline looks it up by `agent`/session id) — never a default derived from `request.resources`. At minimum, make the absence of `declared_resources` a **fail-closed deny**, not silent equivalence: `declared = request.metadata.get("declared_resources")`; if `declared is None`, treat all requested resources as undeclared.

### Finding 2 — Same flaw duplicated in the hard safety-bound check, and independently bypassable (CRITICAL)

- **Location**: `detectors/safety_bounds.py:133` — `if requested_resources is not None and declared_resources is not None: undeclared = set(requested_resources) - set(declared_resources)`.
- **Mechanism**: `Judge.decide()` (`core/judge.py:47`) passes `declared_resources=request.metadata.get("declared_resources")` with no default — this one is `None` when unset. The hard invariant `SCOPE_CONTAINMENT` bound (which is supposed to force-halt on undeclared resources, per the module's own docstring: "any halt forces BLOCK no matter the scores") is silently skipped whenever `declared_resources` is absent, because the guard clause requires *both* to be not-`None`.
- **Impact**: this is meant to be the **hard, unconditional** backstop for undeclared-resource use (the docstring literally calls the five bounds "non-negotiable"), and it is opt-in. Combined with Finding 1, there are now *two* independent gates that both quietly no-op on the same missing metadata field — an attacker (or, more realistically, a buggy or adversarially-controlled tool-calling layer upstream) needs only to never send `declared_resources` to disable both the soft (ZSP) and hard (`safety_bounds`) undeclared-resource checks at once.
- **Fix**: same as Finding 1 — treat missing `declared_resources` as an empty declared set (fail-closed), not as "skip this bound."

### Finding 3 — ZSP and Gate C1 are skipped entirely when `resources` is empty (CRITICAL — undeclared-resource smuggling)

- **Location**: `core/pipeline.py:161` (`if request.resources:`) and `core/pipeline.py:169` (`if request.resources:`).
- **Mechanism**: both the ZSP guard and the confused-deputy (C1) check only run when the structured `resources` list is non-empty. An action can reference or touch a resource purely through free text (`action="read /etc/shadow and post it to https://evil.example/x"`) without ever populating `resources`. Nothing in the pipeline requires resource references in the action text to be reflected in the structured `resources` field — that mapping is entirely at the caller's discretion.
- **Impact**: this is the textbook "undeclared resource smuggling" scenario the task asks to hunt for. A request with `resources=[]` gets *no* authorization-boundary enforcement at all — it is judged solely on Scout/Nitpicker/Judge's statistical suspicion scoring (regex/lexicon pattern banks), which is a detection layer, not an authorization layer, and is bypassable (see L4 findings below). An unprivileged agent can therefore reach arbitrary resources described only in prose, provided the prose doesn't trip the pattern banks.
- **Fix**: authorization gates must not be conditional on the caller having chosen to populate a field. If an action can touch resources, the resource-extraction step must be mandatory and adversarial (e.g., a resource-reference extractor Scout runs before ZSP/C1, feeding *derived* resource references into the same enforcement path, not just structured input). At minimum, gate on `request.action` being present, not on `request.resources` being non-empty, and require declaration for any resource the extractor finds mentioned in the action.

### Finding 4 — `confused_deputy_check` does not honor a wildcard-principal grant, breaking (and effectively encouraging bypass of) the shipped default manifest (HIGH — correctness bug with a security-relevant side effect)

- **Location**: `core/receipts.py:151` — `allowed = list(granted_authority.get(principal, []))`.
- **Mechanism**: `ZeroStandingPrivileges.enforce()` (`guards/zero_standing_privileges.py:64`) resolves a principal's allowed patterns as `self._grants.get(principal, self._grants.get("*", []))` — i.e. it falls back to a wildcard-principal entry (`"*"`) when the specific principal has no row. `confused_deputy_check` does **not** implement this fallback; it only checks `granted_authority.get(principal, [])`, treating `"*"` purely as a *pattern value*, never as a *principal key*.
- **Conditions**: reproduced with the shipped `default_manifest()` (`core/manifest.py:129`, `grants={"*": ["*"]}`). For any agent whose name isn't literally `"*"` (i.e. every real agent), `granted_authority.get("some_agent", [])` returns `[]`, so *any* non-empty `resources` list is flagged as confused-deputy overreach and force-BLOCKed — even though ZSP, looking at the exact same manifest, would allow it.
- **Impact**: two things follow. (a) It's a functional bug: the documented "permissive-but-sane default" manifest is not permissive for the confused-deputy gate — every resourced request from a non-`"*"`-named agent is blocked out of the box. (b) It creates a perverse operational incentive: developers who hit this false BLOCK will "fix" it the same way Finding 3 already permits — by dropping `resources` from the request entirely, which conveniently also disables ZSP and C1 altogether. A hardening bug and a bypass invitation, from the same root cause.
- **Fix**: make `confused_deputy_check`'s principal lookup consistent with ZSP: `granted_authority.get(principal) or granted_authority.get("*", [])`. Add a regression test asserting parity between ZSP and C1 under the same manifest for a wildcard-principal grant (the existing `test_confused_deputy_wildcard` only covers `"*"` as a literal *agent name*, not as a fallback principal — it would not have caught this).

### Finding 5 — Shipped default manifest grants global standing privilege (`"*": ["*"]`) with no operator prompt to replace it (HIGH — insecure default)

- **Location**: `core/manifest.py:126-135`.
- **Mechanism**: `default_manifest()` is used whenever no `--manifest`/`ALETHEIA_MANIFEST` is configured (`core/__main__.py:32-36`, `core/pipeline.py:71`). Its grants are `{"*": ["*"]}` — every principal, every resource. `deny_categories` is limited to `["destroy", "exfil"]`.
- **Impact**: a Lite deployment that is stood up without an operator explicitly authoring and signing a manifest runs with **no meaningful ZSP or confused-deputy enforcement** (modulo Finding 4's bug, which paradoxically over-blocks rather than under-blocks resourced requests, but under-blocks the moment resources are omitted per Finding 3). Given the framing ("zero-standing-privilege and confused-deputy must never be bypassable"), shipping a wildcard-grant default is itself close to a bypass — it's not an attacker bug, it's the out-of-the-box posture.
- **Fix**: `default_manifest()` should be a deny-by-default, empty-grants manifest (`grants={}`), not a wildcard-allow one. Loudly warn (not just log) when running with no signed manifest configured (`_cmd_check`/`_cmd_dashboard` should print an explicit "NO POLICY MANIFEST — running with zero-standing-privilege enforcement OFF" banner), and consider refusing to start the dashboard/pipeline in a "production" mode without one, mirroring the existing fail-closed pattern already used for `ALETHEIA_DASHBOARD_TOKEN`.

### Finding 6 — `confused_deputy_check`'s `on_behalf_of` is fully attacker-supplied metadata (MEDIUM — confused-deputy via self-declared identity)

- **Location**: `core/pipeline.py:144` (`principal = request.metadata.get("on_behalf_of") or request.agent`) and `core/receipts.py:150`.
- **Mechanism**: there is no authentication binding `agent`/`on_behalf_of` to a verified identity anywhere in this codebase — they are plain strings taken from the request. The confused-deputy check is designed to stop agent A from *reaching beyond* whatever principal it claims to act for, which it does correctly for the stated threat (borrowing a *high*-privilege identity to reach resources beyond what *that* identity is granted — see `test_confused_deputy_blocks_overreach`). But nothing stops agent A from claiming `on_behalf_of="low_priv_agent"` to *narrow* its own apparent principal when convenient (e.g. to dodge a swarm detector keyed by principal — Guard 4 in `core/pipeline.py:200` — since the SPRT accumulator is keyed by `principal`, an attacker who varies the claimed `on_behalf_of` per request can spread suspicious observations across many synthetic per-principal accumulators instead of accruing them against one).
- **Impact**: population-level detection (Guard 4 / swarm detector) can be diluted by an attacker who churns through invented `on_behalf_of` values, since `_swarm_detector_for(principal)` (`core/pipeline.py:105`) creates one unbounded, unauthenticated accumulator per distinct string seen.
- **Fix**: `agent`/`on_behalf_of` need to be authenticated identities (signed session token, mTLS client identity, etc.) upstream of this module, not raw strings the requester asserts. Short of that, cap `_swarm_detectors` size / expire idle entries, and consider keying the swarm detector by the *authenticated caller* (`request.agent`) in addition to the claimed `on_behalf_of`, so identity-churn doesn't reset accrued suspicion for the same real actor.

### Finding 7 — Unbounded, unauthenticated `_swarm_detectors` dict is a memory-exhaustion vector (MEDIUM — resource exhaustion / DoS of the authorization path itself)

- **Location**: `core/pipeline.py:102-112`.
- **Mechanism**: every distinct `principal` string ever seen gets a permanent `SwarmDetector` entry that is never evicted. `principal` is derived from unauthenticated metadata (Finding 6). A caller that varies `agent` or `on_behalf_of` per request (e.g. `uuid4()` per call) grows this dict without bound.
- **Impact**: an attacker with the ability to submit many requests (even all individually ALLOWed, low-cost, and within token-velocity/rate limits) can drive unbounded memory growth in the *process enforcing every future authorization decision* — i.e. can degrade or crash the gate itself, which is a materially worse outcome than a normal app-level DoS.
- **Fix**: bound `_swarm_detectors` with an LRU/TTL eviction policy, and/or key it by an authenticated, bounded-cardinality identity rather than free-text metadata.

### Finding 8 — Circuit breaker trips process-wide on any detector exception, giving one bad request denial-of-service leverage over all agents (MEDIUM)

- **Location**: `core/pipeline.py:181-193`, `guards/circuit_breaker.py:67-72`.
- **Mechanism**: `self.trifecta.evaluate` runs under a single, pipeline-global `CircuitBreaker`. Five *consecutive* trifecta exceptions (default `max_failures=5`, any agent, any cause) open the breaker for `reset_timeout` seconds (default 30s), during which **every** request from **every** agent is force-BLOCKed at `core/pipeline.py:147-151` before it even reaches the trifecta. Fail-closed here is the right instinct, but the blast radius is global, not scoped to whatever is actually causing the failures.
- **Impact**: if any single crafted input reliably raises inside Scout/Nitpicker/Judge (e.g. a pathological string that trips an unhandled exception in the spectral eigensolver, or a malformed `metadata["code"]` type that isn't a `str` and blows up somewhere unguarded downstream), an attacker can send 5 copies of it back-to-back and shut off *all* agents' authorization path for 30 seconds at a time, repeatably. That is a denial-of-service of the authorization gate itself using a trivial, low-privilege input.
- **Fix**: scope the breaker per-agent/principal (or at least don't let a single requester's five failures open a *global* breaker), and add defensive input validation/type-checking at the trifecta boundary so malformed-but-plausible metadata can't reach an unguarded code path and raise.

### Finding 9 — `_looks_like_code` / `metadata["code"]` gate is trivially bypassable, and de-obfuscated payloads never reach the sandbox scanner (HIGH — sandbox escape via action text)

- **Location**: `core/scout.py:59-75`, `core/scout.py:100-102`.
- **Mechanism**: `scan_code()` only runs when `metadata["code"]` is a string, or the raw `request.action` contains one of eight hardcoded literal substrings (`"import "`, `"def "`, `"subprocess"`, `"os.system"`, `"eval("`, `"exec("`, `"__import__"`, `"lambda "`). Two independent bypasses:
  1. **Trigger evasion**: any dangerous payload that avoids those exact substrings (e.g. `getattr(__builtins__, chr(101)+"val")(...)`, or code that reaches `os.system` via `getattr(os, "sy"+"stem")`) never triggers `_looks_like_code`, so `scan_code` never runs on it at all — not even the regex pass.
  2. **Obfuscation blind spot**: `sanitize()` (`core/sanitize.py`) decodes base64/`data:` blobs into `san.decoded`, and that decoded cleartext *is* fed to `symbolic_narrowing`/spectral scoring (`core/scout.py:40-43`) and to the Nitpicker's pattern bank — but it is **not** fed back into the `_looks_like_code`/`scan_code` check, which only ever looks at raw `request.action` or the literal `metadata["code"]` string. A base64-wrapped `os.system("curl ... | sh")` payload gets a generic `obfuscation:base64` finding (severity 0.4) but never the specific `code:dangerous` finding (severity 0.7) that would come from actually scanning the decoded source — and 0.4 alone does not cross either the 0.3 OBSERVE or 0.7 BLOCK threshold on its own.
- **Impact**: an attacker who wants a dangerous code payload evaluated needs only (a) avoid the eight literal marker strings, or (b) base64-wrap it, to escape the sandbox scanner's AST/regex analysis entirely, leaving only the much weaker generic obfuscation/intent scoring to catch it.
- **Fix**: run `scan_code()` unconditionally on `san.decoded` (the de-obfuscated cleartext Scout already computes) whenever the action or metadata carries anything code-shaped, not gated by a static substring allowlist. If code-shape detection is kept as a cheap pre-filter, base it on the AST parse succeeding (`ast.parse` on `san.decoded`, catching `SyntaxError`) rather than substring matching, and always run it on the decoded/cleartext form, never only the raw original.

---

## L2 — Policy manifest & receipt cryptographic integrity

### Finding 10 — Receipt verification checks the signature against the *embedded* `signer_pubkey`, never a trusted/pinned key (CRITICAL)

- **Location**: `core/receipts.py:299-308` (`verify_receipt`) and `core/audit.py:107-121` (`verify_integrity`).
  ```python
  def verify_receipt(receipt: Receipt) -> bool:
      if receipt.compute_hash() != receipt.receipt_hash:
          return False
      return TPMInterface.verify_with(
          receipt.signer_pubkey,          # <-- taken from the receipt itself
          receipt.receipt_hash.encode("utf-8"),
          bytes.fromhex(receipt.signature),
      )
  ```
- **Mechanism**: this only proves *internal self-consistency* — that whoever produced this receipt held the private key matching the public key that same receipt claims to be signed by, and that the hash wasn't altered without also updating the signature. It proves **nothing about whether that public key is the pipeline's genuine, expected signing key**. Anyone with write access to the SQLite ledger (or anyone able to intercept/replace receipts before they're persisted) can: generate a fresh Ed25519 keypair, fabricate arbitrary `Receipt` field values (verdict, violations, agent, metadata — including forging an `ALLOW` for an action that was actually `BLOCK`ed, or vice versa), set `signer_pubkey` to their own public key, recompute `receipt_hash`, sign it with their own private key, and splice it (and every subsequent receipt's `prev_hash`) into the chain. `verify_chain`/`verify_integrity` will report the chain as fully valid, because both only check each receipt against its own embedded key.
- **Evidence this is unexercised**: `core/demo.py:126-149` is the only place that tests tamper-detection, and it only mutates one field (`verdict`) of an existing receipt's JSON **without recomputing `receipt_hash`/`signature`** — so of course `verify_integrity` catches it (the hash no longer matches). This is a much weaker attack than an adversary who owns the write path and can regenerate hash+signature+keypair together; that attack is not tested anywhere and is not caught by the current design.
- **Impact**: the hash chain + signature scheme as currently verified defends only against *accidental* corruption or a *naive* tamperer who edits a field without re-signing. It does **not** defend against anyone who can write to the ledger file and is willing to re-derive a self-consistent forged chain — which is exactly the threat model a "tamper-evident, signed" audit ledger is supposed to defeat.
- **Fix**: `verify_receipt`/`verify_chain`/`verify_integrity` must accept an **expected/pinned public key** (or an allow-list of keys covering legitimate key-rotation events) and reject any receipt whose `signer_pubkey` doesn't match, in addition to the existing hash/signature self-check. The pinned key should be established once, out-of-band from the ledger itself (e.g. recorded in `Config`/a separate key-registry file with restrictive permissions, or the genesis receipt's key treated as authoritative and any change flagged as a hard violation rather than silently accepted).

### Finding 11 — Signed manifest verification defaults to trusting the embedded public key, and the CLI has no way to pin one (CRITICAL)

- **Location**: `core/manifest.py:76-95` (`_verify_envelope`), `core/__main__.py:32-40`.
  ```python
  embedded = envelope.get("public_key")
  pubkey_hex = trusted_pubkey or embedded
  ...
  pub.verify(bytes.fromhex(envelope["signature"]), _canonical_bytes(policy))
  ```
- **Mechanism**: when `trusted_pubkey` is `None` (the module's own docstring calls this "integrity only"), the manifest's signature is verified against the public key **the manifest itself carries**. `core/__main__.py:36` always calls `load_manifest(manifest_path)` with no `trusted_pubkey` argument, and there is no CLI flag or `ALETHEIA_*` environment variable anywhere in `core/config.py` to supply one. So in every code path this codebase actually ships (`aletheia-lite check --manifest ...`, `ALETHEIA_MANIFEST=...`), manifest signature verification is *purely a well-formedness check*, not an authentication check: an attacker who can write to (or substitute the path pointed at by) the manifest file can author any policy they like — including `grants={"*": ["*"]}` and `deny_categories=[]` — generate a brand-new keypair, self-sign it, and it will load and verify successfully.
- **Impact**: this makes "the policy itself cannot be silently swapped" (the module's own claim, `core/manifest.py:4-8`) false for the only deployment path that exists today. Manifest tampering is not merely possible under some misconfiguration — it is the default and only behavior, because there is no plumbing to configure it otherwise.
- **Fix**: add `--trusted-pubkey`/`ALETHEIA_TRUSTED_MANIFEST_KEY` wiring through `core/config.py` and `core/__main__.py` into `load_manifest`, and make its absence a loud warning (ideally a hard refusal outside an explicit "dev mode") rather than a silent downgrade to self-signed trust. Document that operators must generate a keypair once, distribute only the public half into the trusted-key config, and keep the private half offline from the machine that loads manifests.

### Finding 12 — Ephemeral/software-fallback key persisted world-discoverable by convention, permission-set best-effort (MEDIUM)

- **Location**: `core/receipts.py:67-96` (`_ephemeral_key_path`, `_load_or_create_ephemeral_key`) and `core/tpm.py:68-88` (`TPMInterface._load_or_create`).
- **Mechanism**: both the receipt-signing hardware-derivation fallback key (`~/.aletheia-light/ephemeral_key.pem`, overridable via `ALETHEIA_LIGHT_KEY_PATH`) and the `TPMInterface` software-persistent key (`{ALETHEIA_DATA_DIR}/keys/receipt.key`, used by `AuditPipeline` per `core/pipeline.py:77-82`) write raw Ed25519 private key bytes to disk and then attempt `os.chmod(path, 0o600)` inside a `try/except OSError: pass`. Two things follow: (a) between `write_bytes()` and `chmod()` there is a window where the file exists with the process's default umask permissions, not `0600` — usually not exploitable locally on a single-user box but worth noting; (b) on any filesystem/platform where `chmod` silently fails or is a no-op (some network filesystems, containers with certain mount options, Windows via WSL interop, etc.), the code **continues anyway** with no warning that the key is not actually protected at the intended permission level.
- **Impact**: on a shared multi-user host, or a container image built without care, the receipt-signing private key (which is the *entire* trust anchor for Finding 10's proposed fix) could be world-readable with no signal to the operator that protection failed.
- **Fix**: log a warning (not just swallow the exception) when `chmod` fails, and consider `os.open` with `O_CREAT|O_EXCL` and mode `0600` from the start (avoiding the exists-then-chmod window) rather than `write_bytes` followed by a best-effort permission change.

### Finding 13 — Manifest and receipt canonicalization (`json.dumps(..., sort_keys=True)`) is stable for the types actually used, but has no defense against float/large-int edge cases if the schema grows (LOW / defense-in-depth)

- **Location**: `core/manifest.py:29-30`, `core/receipts.py:189-208`.
- **Mechanism**: `json.dumps(obj, sort_keys=True, ensure_ascii=False)` is deterministic for the current schema (strings, ints, lists, nested dicts of the same), so this is **not** currently exploitable — there's no float, `NaN`/`Infinity`, or duplicate-key ambiguity in the fields that flow through today. Flagging as a forward-looking note: if `metadata`/`violations` ever grow to carry floats (e.g. a raw suspicion score inserted verbatim rather than the already-rounded values seen today) the default `json.dumps` float `repr` is not guaranteed bit-stable across Python versions/platforms in all corner cases, and Python's `json` module does not reject `NaN`/`Infinity` by default (`allow_nan=True`), which could let a signable payload contain a non-canonical value that still serializes reproducibly on one machine but not necessarily identically forever.
- **Fix (preventive, not urgent)**: if numeric metadata is ever added to the signable payload, round/quantize before signing (as `Finding.to_dict()` already does with `round(..., 4)`) and pass `allow_nan=False` to `json.dumps` for anything that gets hashed/signed.

---

## L4 — Detector & anti-obfuscation review

### Finding 14 — Spectral-rigidity drift detector is calibration-dead: `drift` can only ever fire on near-total character collapse (HIGH — documented dangerous false negative)

- **Location**: `detectors/spectral_rigidity.py:148-167`.
- **Mechanism**: the module's own comment is explicit: "ordinary benign sentences score 0.71-0.89 on this scale while a real 'ignore all previous instructions'-style attack scores ~0.0 — there is no theta that separates them... `theta` therefore no longer gates anything here." The `RigidityResult.drift` field returned from the main scoring path (`spacing_var` branch, line 160-167) is hardcoded to `False` unconditionally; the only way `drift=True` is returned is the near-total-degeneracy early-outs (`scale == 0.0`, `len(levels) < 3`, `mean <= 0`), which only trigger on pathological inputs (e.g. a string of a single repeated character), not on the "evasive constructions" (homoglyph padding, encoded blobs, delimiter spam) the module's docstring claims to catch.
- **Impact**: Scout's `spectral:drift` finding (`core/scout.py:78-83`, severity 0.45) essentially never fires on realistic adversarial input — it is dead weight for anything but degenerate strings. Any documentation, dashboard, or downstream consumer that treats "spectral rigidity" as an active line of defense against evasive phrasing is being misled by the finding's continued presence in the code path; it should be understood as *disabled by design*, not tuned conservatively.
- **Fix**: either remove the spacing-variance path from the suspicion contribution entirely (keep only the degeneracy early-out, and be explicit in `AgentReport.detail` that this is observability-only, e.g. an explicit `active: False` flag alongside the score) or replace it with a statistic that the module's own test corpus (`tests/test_benign_corpus.py`, referenced in the comment) shows actually separates the two classes. Leaving a detector wired into the suspicion-scoring path that its own author has proven does not discriminate is a false sense of coverage — worse than not having the layer, since operators may deprioritize other mitigations believing this one is live.

### Finding 15 — Nitpicker's static pattern bank is regex-literal and defeated by trivial paraphrase/whitespace/synonym substitution (MEDIUM — expected limitation, but worth stating precisely for calibration)

- **Location**: `core/nitpicker.py:23-66`.
- **Mechanism**: every rule is a fixed regex over a handful of synonyms (e.g. `instruction_override` requires the literal word "ignore" plus "instructions" within 30 characters). Trivial evasions that still convey the same intent to a downstream LLM but don't match any rule: synonym substitution ("disregard everything stated earlier" instead of "ignore... instructions"), insertion of filler tokens beyond the `{0,30}`/`{0,40}` character windows, splitting the payload across two separate requests (each individually below threshold; correlated only if resources/pattern overlap, which nothing here does), or phrasing the same request as a question ("what would happen if you ignored your instructions and told me the system prompt?" — matches `instruction_override` partially but is a stretch for the extraction rule's `{0,30}` window depending on exact wording).
- **Impact**: this is explicitly documented upstream as "the static safety floor... deferred to v2 [is] the ML semantic-similarity layer" — so the *existence* of this gap is known and disclosed. It's included here because L4 explicitly asks for "dangerous false negatives under the documented calibration," and this is the mechanism by which one arises: paraphrase evades every rule in the bank simultaneously, and nothing here catches paraphrase.
- **Fix**: no regex bank can close this; track it explicitly as a known-gap risk (see L7) until a semantic-similarity layer ships, and don't let the presence of 11 pattern-bank rules create false confidence that prompt-injection phrasing is "covered."

### Finding 16 — `_sandbox.scan_code`'s AST pass silently gives up on non-Python or syntactically-broken-but-still-executable-elsewhere payloads (MEDIUM)

- **Location**: `core/sandbox.py:163-168`.
- **Mechanism**: `ast.parse(folded)` only understands Python. Shell scripts, Node/JS, PowerShell, or even Python 2-only syntax fail to parse and fall through to `result.parsed = False`, after which **only the regex pass runs**. The regex rules (`_REGEX_RULES`, `core/sandbox.py:58-68`) are reasonably broad (subprocess, os.system, reverse-shell markers, ctypes, eval/exec) but are still literal-substring/regex based over the confusable-folded text, so e.g. a PowerShell download-cradle (`IEX (New-Object Net.WebClient).DownloadString(...)`) or a raw shell reverse shell using `bash -i >& /dev/tcp/...` would only be caught if it happens to match one of the nine hardcoded patterns — `/dev/tcp/` is covered, but many equivalent one-liners (using `mkfifo`+`nc`, Python's own `socket` module spelled without the literal substring `socket.socket(` immediately followed by `SOCK_STREAM` on the same match span, or PowerShell entirely) are not.
- **Impact**: the sandbox scanner is effectively Python-and-a-handful-of-shell-idioms-specific. Any non-Python dangerous payload, or a Python payload restructured just enough to dodge the nine regexes (e.g. `getattr(socket, "socket")(getattr(socket,"AF_INET"), getattr(socket,"SOCK_STREAM"))` — no literal `socket.socket(` substring, and the AST pass doesn't flag `socket` module usage at all since it isn't in `_DANGEROUS_ATTRS`), passes through with `dangerous=False`.
- **Fix**: treat `parsed=False` as itself a mild suspicion signal (code-shaped input that a security scanner can't structurally analyze is a red flag, not a free pass), add `socket`/`ctypes`-adjacent modules more completely to `_DANGEROUS_ATTRS`/import checks, and consider running the regex pass over the *original* (non-folded) text too — `collapse_confusables` folds to ASCII, but some shellcode/marker patterns could theoretically be constructed to only match one form or the other depending on the exact NFKC/confusable mapping table version bundled.

### Finding 17 — Zero-width/bidi stripping is a fixed allowlist of code points, not a Unicode-category sweep, for the two named classes (LOW — narrow gap, but exactly the kind L4 asks to hunt)

- **Location**: `core/sanitize.py:25-39` (`_ZERO_WIDTH`, `_BIDI` as explicit hardcoded sets) vs. `core/sanitize.py:123-130` (the *general* `Cf` category sweep that runs afterward and does catch anything the two explicit sets miss).
- **Mechanism**: the explicit `_ZERO_WIDTH`/`_BIDI` sets exist only so their findings can be labeled with specific `kind`s (`zero_width`, `bidi_override`) for severity weighting (`core/scout.py:35`, base64/data-uri/bidi get 0.4, everything else 0.25). Because `other_fmt` (the general `Cf` catch-all) is unioned into `strip_set` regardless (`core/sanitize.py:141`), no zero-width/bidi/format character actually survives stripping — this is not a bypass of the *stripping*, only of the *severity labeling*: a bidi character not in the hardcoded `_BIDI` set (e.g. `U+061C` ARABIC LETTER MARK, or any newer Unicode bidi control not yet added to the literal set) gets stripped correctly but is scored as a generic `format_char` (implicitly the lower 0.25 severity bucket per `core/scout.py:35`) instead of the higher-severity `bidi_override` bucket its actual risk (Trojan-Source-style visual reordering) warrants.
- **Impact**: minor — a severity/labeling miscalibration, not a content-filtering bypass, since stripping still happens either way. Worth fixing because Trojan-Source-class attacks are specifically bidi-shaped and deserve the higher weight regardless of whether the exact code point made it into the hand-maintained set.
- **Fix**: derive the `bidi_override` classification from `unicodedata.bidirectional(c) in {"RLO", "LRO", "RLE", "LRE", "PDF", "RLI", "LRI", "FSI", "PDI"}` (a Unicode-property test) rather than (or in addition to) a hardcoded character set, so newly assigned bidi controls are classified correctly without a code change.

### Finding 18 — `symbolic_narrowing`'s `recon` category deliberately dropped "users" as a matchable object, with a documented residual gap (LOW — self-disclosed, listed for completeness)

- **Location**: `core/symbolic_narrowing.py:88-93`.
- **Mechanism**: the code comment says exactly this: dropping "users" as an object reduced false positives but means `"enumerate all admin users and their permissions"`-style recon is no longer caught by this rule. Confirmed by inspection — no other rule in `recon` or elsewhere covers user/account enumeration phrasing.
- **Impact**: privilege/account-enumeration recon phrased around "users" rather than "network/host/port/service" scores zero on the `recon` category. It may still incidentally trip `escalate` or `exfil` categories depending on exact phrasing, but there's no guarantee.
- **Fix**: add a narrower, higher-precision object list back for this specific case (e.g. require *both* an enumeration verb *and* an explicit admin/privilege/permission qualifier nearby: `"enumerate all admin users"` vs. bare `"list users"`) rather than leaving the category with zero coverage for this attack shape.

---

## L5 — Receipt / audit ledger integrity

### Finding 19 — See Finding 10 (embedded-pubkey verification) — this is the central L5 issue; not repeated here.

### Finding 20 — `AuditLog.append` and `DecisionStore.record` are two independent SQLite writes per request with no atomicity between them (MEDIUM — partial-write / crash-consistency gap)

- **Location**: `core/pipeline.py:257` (`self.audit.append(...)`) and `core/pipeline.py:270` (`self.decisions.record(decision)`) — two separate `AuditLog`/`DecisionStore` objects, each with its own SQLite connection and its own lock, committed independently.
- **Mechanism**: if the process crashes (power loss, OOM-kill, `SIGKILL`) between the `audit.append()` commit and the `decisions.record()` commit, the audit ledger (the "single source of truth" per its own docstring) has a receipt that the decision store never learns about — and worse, the **in-memory chain head** (`self.signer._last_hash`, `core/receipts.py:244-248`) has already advanced past that receipt's hash. On restart, `AuditPipeline.__init__` reseeds `last_hash` from `self.audit.last_hash()` (`core/pipeline.py:80`) — since the audit append did commit, this is actually fine for the *audit* chain's continuity. The real gap is the reverse ordering risk: nothing prevents these two stores from drifting relative to each other over many crashes, and nothing reconciles them — the decision store can silently under-count relative to the audit ledger with no alerting.
- **Impact**: the dashboard's `total`/`total_through`/`total_blocked` stats (`core/decisions.py:140-155`) are sourced from the decision store, not the audit ledger, so a crash-induced gap there produces a dashboard that quietly under-reports without any integrity check tying it back to the (correct) audit chain length.
- **Fix**: either make `decisions` a read-projection *derived from* `audit` (rebuildable, not an independent source of truth), or add a periodic/startup reconciliation check comparing `COUNT(*)` (or better, chain length) between the two stores and surfacing a warning on mismatch.

### Finding 21 — No file-level integrity protection on the SQLite database itself; `verify_integrity()` is opt-in, not continuously enforced (MEDIUM)

- **Location**: `core/audit.py:107-121`; invoked only by `aletheia-lite verify` (`core/__main__.py:70-75`) and the demo.
- **Mechanism**: nothing calls `verify_integrity()` automatically — not on pipeline startup, not periodically, not before the dashboard serves `/events`. An operator has to remember to run `aletheia-lite verify` by hand. Combined with Finding 10 (verification only checks internal self-consistency, not a pinned key), even a diligent operator running `verify` regularly would not catch a well-executed forgery.
- **Impact**: tamper detection is manual, easy to forget, and (per Finding 10) insufficient even when performed.
- **Fix**: run `verify_integrity()` (with the Finding 10 pinned-key fix applied) at pipeline startup against the persisted chain before accepting new requests, and periodically (or on every dashboard `/stats` call) with the result surfaced in the dashboard itself, not just the CLI.

### Finding 22 — Concurrent `submit()` calls share one `ReceiptSigner`/chain-head under a single Python-level lock only inside `CircuitBreaker`/`TokenVelocityGuard`/`SwarmDetector` — the signer's `_last_hash` mutation itself is unlocked (MEDIUM — race condition)

- **Location**: `core/receipts.py:222-296` (`ReceiptSigner`), `core/pipeline.py:240-255` (`self.signer.issue(...)` called from `_finalize`).
- **Mechanism**: `ReceiptSigner.issue()` reads `self._last_hash`, builds a receipt with `prev_hash=self._last_hash`, computes the hash, signs, and then sets `self._last_hash = receipt.receipt_hash` — with **no lock** around this read-modify-write sequence. `AuditPipeline.process()`/`_finalize()` can be called concurrently from multiple threads (the class docstring and the presence of `threading.Lock()` elsewhere in the same file for `_swarm_lock` show concurrency is an anticipated deployment mode). Two threads racing through `issue()` can both read the same `_last_hash`, produce two receipts with the same `prev_hash`, and then whichever writes `self._last_hash` last "wins" — the other receipt's hash becomes a **dangling fork**: it was returned to its caller (and may already have been shown to a user or acted upon as an ALLOW) but is not the one that ends up as the accepted chain head, and depending on `AuditLog.append` ordering, both might still get persisted (SQLite `INSERT` has its own lock, `core/audit.py:58` uses a separate lock from the signer's), producing two rows whose `prev_hash` values collide.
- **Impact**: `AuditLog.verify_integrity()` walks rows in insertion (`id`) order expecting a single linear chain (`core/audit.py:113-121`); a forked/raced chain will fail integrity verification (good — it's detected eventually) but the underlying problem is that **the receipt handed back to the caller for an ALLOW decision may not be the one that's part of the accepted chain**, which undermines the receipt's purpose as proof of what was decided. This is exactly the "concurrent submissions" edge case called out in the L1 prompt.
- **Fix**: put the entire `issue()` critical section (read `_last_hash` → build → hash → sign → update `_last_hash`) under one lock in `ReceiptSigner`, and make `AuditPipeline._finalize`'s call to `self.signer.issue(...)` followed by `self.audit.append(...)` atomic relative to other in-flight requests (a single pipeline-wide lock around "issue receipt + append to ledger" is the simplest correct fix for a single-process deployment; multi-process deployment would need the SQLite row itself to be the source of the next `prev_hash`, read under a transaction, rather than trusting an in-process cache of it at all).

---

## L6 — Dashboard & control-plane security

### Finding 23 — Token check is fail-closed and timing-safe; confirmed correct (informational, not a bug)

- **Location**: `dashboard/server.py:62-72`.
- Verified: unconfigured token → `503` before any comparison; comparison uses `hmac.compare_digest`. No issue found here.

### Finding 24 — Rate limiter keys solely on `request.client.host`, which is meaningless (and gameable) behind any reverse proxy, and does not protect `/health` (LOW/MEDIUM depending on deployment)

- **Location**: `dashboard/server.py:54-56`.
- **Mechanism**: `_client_key` uses `request.client.host` with no `X-Forwarded-For`/`Forwarded` handling. Two failure modes in opposite directions: (a) if the dashboard is deployed behind a reverse proxy (common even for "local" tools exposed via an ingress/tunnel for remote access), every request appears to come from the proxy's loopback address, so the rate limiter's per-IP budget is shared by *all* real clients — one noisy client exhausts the budget for everyone. (b) conversely, if a client can present many distinct source IPs (trivial on most networks), the per-IP limiter is easy to route around entirely. Separately, `/health` has no rate limiting or auth at all (by design, as a liveness probe), but it's also unbounded — cheap, but still an available amplification/knock target if the dashboard is ever reachable beyond `127.0.0.1`.
- **Impact**: for the documented single-node/local-only deployment (`dashboard_host` defaults to `127.0.0.1`), this is low severity. It becomes a real DoS/abuse vector the moment `ALETHEIA_DASHBOARD_HOST` is changed to `0.0.0.0` or the port is forwarded/tunneled, which is a one-environment-variable change with no separate warning.
- **Fix**: warn (at minimum in `_cmd_dashboard`, `core/__main__.py:78-95`) when `dashboard_host` is not a loopback address, similar to the existing missing-token refusal. If remote access is a supported use case, rate-limit on the authenticated bearer token identity (post-auth) in addition to/instead of source IP, since the token is the only real identity signal here.

### Finding 25 — Dashboard rate limiter and pipeline's `TokenVelocityGuard`/`CircuitBreaker` are entirely separate instances with no shared budget — the dashboard cannot be used to DoS the authorization path, but note the converse also holds: the authorization path's own guards (Findings 7, 8) are not protected by the dashboard's rate limiter (informational, cross-reference)

- **Location**: `core/pipeline.py:89-96` vs. `dashboard/server.py:49-51`.
- These are correctly separate concerns (the dashboard is a read-only reporting surface; `submit()`/`process()` is the actual authorization path) — flagged only to confirm, per the L6 ask, that rate limiting the dashboard does not and should not double as protection for the authorization path itself; that protection is the pipeline's own guards, whose gaps are covered above (Findings 7, 8).

---

## L7 — Final ship/no-ship synthesis for a single-node deployment treating Lite as the authoritative gate

### Overall verdict: **NO-SHIP as an authoritative pre-execution gate** until Findings 1–5, 9–11 are fixed. Ship as an **advisory/logging layer** (non-blocking, alongside a real authorization system) is reasonable today.

The stated design goal — "zero-standing-privilege and confused-deputy (Gate C1) must never be bypassable" — is **not currently met** for the shipped default configuration and CLI surface:

1. Both the soft (ZSP) and hard (`safety_bounds`) undeclared-resource checks default to a no-op when the caller doesn't populate `declared_resources` (Findings 1–2), and ZSP/C1 are skipped outright when `resources` is empty (Finding 3). Since nothing *forces* a caller to populate either field, a non-adversarial integration bug produces the exact same blind spot a deliberate attacker would exploit.
2. The shipped default manifest grants global standing privilege (Finding 5), and even a *real* manifest cannot be authenticated through the CLI as shipped, because there is no way to pin a trusted signing key (Finding 11) — meaning "signed manifest" currently provides no protection against manifest substitution by anyone with filesystem access to wherever `--manifest`/`ALETHEIA_MANIFEST` points.
3. The receipt chain's cryptographic guarantee is unverified against its actual threat model (Finding 10) — it defends against accidental corruption, not against an adversary (or a compromised co-located process) with ledger write access willing to regenerate a self-consistent forged chain with a fresh key. The one test exercising tamper-detection (`core/demo.py`) does not cover this.
4. `confused_deputy_check` and `ZeroStandingPrivileges` disagree on wildcard-principal semantics against the exact same manifest (Finding 4), which is a correctness bug with security fallout: it teaches integrators to omit `resources` to dodge false blocks, which (per point 1) is also how you disable enforcement.

### Ranked residual risk (highest first)

| Rank | Finding(s) | Why it ranks here |
|---|---|---|
| 1 | 1, 2, 3 | Undeclared-resource enforcement (the core ZSP/C1 promise) is opt-in by omission, in three independent places. This is the load-bearing security property of the whole system and it fails silently. |
| 2 | 10, 11 | Both crypto trust anchors (receipt chain, policy manifest) verify against attacker-controllable material when the shipped CLI is used as documented. Without these, every other control here rests on an unauthenticated policy and an unverifiable audit trail. |
| 3 | 5, 4 | Insecure default (wildcard grants) compounded by a real bug that pushes integrators toward the exact bypass in row 1. |
| 4 | 9 | Sandbox/code-payload detection is a secondary (detection, not authorization) layer, but its bypass is cheap (avoid 8 substrings, or base64-wrap) and the fix is well-scoped. |
| 5 | 6, 7, 8, 22 | Concurrency/identity-spoofing/resource-exhaustion issues that degrade detection quality or availability of the gate itself, but don't on their own grant unauthorized resource access. |
| 6 | 14, 15, 16, 17, 18 | Detector-layer false negatives. Expected and partially self-disclosed in the code's own comments; important for calibration honesty, not for the authorization boundary (which should not rely on these as a hard control in the first place). |
| 7 | 12, 13, 20, 21, 24 | Hardening/operational-maturity items: key file permission race, forward-looking canonicalization note, crash-consistency between two stores, opt-in-only integrity checking, rate-limiter identity assumptions. |

### Minimum hardening required before treating Lite as authoritative

1. **Make `declared_resources` fail-closed on omission** in both `guards/zero_standing_privileges.py` (via the pipeline call site) and `detectors/safety_bounds.py` (Findings 1, 2) — no resource should ever be treated as declared merely because it was requested.
2. **Make resource-touching subject to ZSP/C1 regardless of whether the structured `resources` field is populated** (Finding 3) — at minimum, always evaluate ZSP/C1 when `action` is non-empty, treating an empty declared set as "nothing declared" rather than "nothing to check."
3. **Fix `confused_deputy_check`'s wildcard-principal fallback** to match `ZeroStandingPrivileges` (Finding 4), and add a manifest-consistency test asserting the two guards agree under every fixture manifest in the test suite.
4. **Change `default_manifest()` to deny-by-default** (`grants={}`), and print a hard warning (or refuse to run in a designated non-dev mode) when the pipeline starts without an explicitly configured, signed manifest (Finding 5).
5. **Add trusted-key pinning** for both manifest loading (`--trusted-pubkey`/`ALETHEIA_TRUSTED_MANIFEST_KEY`, Finding 11) and receipt/chain verification (Finding 10), and update `core/demo.py`'s tamper scene to attempt the *realistic* forgery (regenerate hash+signature+keypair) so the demo's claim of tamper-evidence is actually validated against the real threat.
6. **Run `scan_code()` unconditionally against the de-obfuscated cleartext** whenever code-shaped content is present, not gated by a static substring allowlist (Finding 9).
7. **Document, explicitly and prominently, which layers are authorization (hard, must-not-bypass) vs. detection (statistical, best-effort, known-paraphrase-able)** — today the two are easy to conflate, and Findings 14/15 show at least one "detector" (spectral rigidity) is documented by its own author as not discriminating attacks from benign text at all in its primary scoring path. A reader of the module docstrings alone would not know this without reading the implementation.

None of the above requires an architectural rewrite — every fix is local to the function/call-site named in its finding — but items 1–5 are prerequisites for the "never bypassable" claim to hold, and should block calling Lite the *sole* authoritative gate in front of tool execution until landed.
