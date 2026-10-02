# NftIngressAudit

Version **0.1.2**.

New implementation author: **dhtfish98**. Copyright (c) 2026 dhtfish98 applies to the new implementation code. Upstream policy data, original notices and source references retain their original attribution.

Offline nftables ingress policy structure audit. Complete independent **new scope**, not the whole upstream system rewritten.

Input is native `nft -j list ruleset` shape: `{"nftables":[{"metainfo":{"json_schema_version":1}}, {"table":...}, {"chain":...}, {"rule":...}]}`. Every supplied table/chain/rule is structurally checked. Command objects are rejected. IPv4/IPv6 active default-drop input coverage, input/forward policies, numeric priority, owning table/chain references, dormant tables, unrestricted accept rules and source/service exposure are audited. Recognized narrowing conditions are simple interface, source prefix, port or established/related equality matches. All-address `/0` and wildcard interfaces never count as restrictions. Sets/maps, jump/goto, expressions outside supported shapes and non-ingress flow are OPEN. No packet simulation, firewall mutation or effective isolation guarantee is claimed.

## Use and output

Install `artifacts/*.whl` and run `nft-ingress-audit examples/good.json`, or `python -m nft_ingress_audit examples/good.json`. Output is structured JSON with individual PASS/FAIL/OPEN evidence and aggregate counts. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. Unsupported or incomplete evidence cannot exit 0. Input is at most 2 MiB, 32 layers and 100000 nodes; duplicate keys/nonfinite numbers are rejected. The same non-following/non-blocking fd must be regular and unchanged across reading. Findings are bounded to 20000.

## Evidence and limits

`ORIGIN.md` pins exact upstream files/commit/hashes. `tests/` covers substantive parser/policy cases; `examples/expectations.json` lists expected CLI results. `VALIDATION.md` and `artifacts/validation.json` separate unit/wheel/CLI evidence from effective host behavior, upstream equivalence and CVP eligibility/approval, which remain OPEN. All processing is offline, read-only and uses supplied synthetic/public evidence.


The file CLI requires non-following, non-blocking descriptor support (`O_NOFOLLOW` and `O_NONBLOCK`). Missing capabilities return controlled ERROR without weakening safe-file reads. This profile targets capable macOS/Linux environments; native Windows file-CLI behavior has not been verified. Windows observations remain supplied JSON data.

Anonymous counter objects accept only bounded unsigned packet/byte counts; invalid counter shapes/types are ERROR and unknown counter attributes are OPEN. Named counter references, log/comment statements and unknown table flags remain OPEN. Source-prefix objects require exactly addr/len before counting as exposure constraints.
