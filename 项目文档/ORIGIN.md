# Origin and boundaries

New implementation author: **dhtfish98**. Copyright (c) 2026 dhtfish98 applies to the new implementation code. Upstream policy data, original notices and source references retain their original attribution.

This is an independent, source-informed, complete **new-scope** defensive tool. It is not a claim to rewrite all of the upstream project or to be behaviorally equivalent to it. Offline configuration evidence does not prove effective runtime protection, authorization, CVP eligibility, or approval.

Upstream references are frozen below. Only policy data explicitly named in NOTICE is bundled; other upstream implementation code and documentation are not copied into the wheel. Source license labels describe references; the new implementation license is MIT.

- `COPYING` at `1afa761d59834c61a30bdf7ffb52a0afaa7d40f4`, SHA-256 `4ee1e51baf5f3166712fa0c3e01338c7257e50ddef245d28bb14ad68f6070ba5`: https://git.netfilter.org/nftables/tree/COPYING?id=1afa761d59834c61a30bdf7ffb52a0afaa7d40f4
- `doc/libnftables-json.adoc` at `1afa761d59834c61a30bdf7ffb52a0afaa7d40f4`, SHA-256 `d5dfd4fe2ffed428b8698fa86641fdd03fdc733276460f74bccb41eb06645a00`: https://git.netfilter.org/nftables/tree/doc/libnftables-json.adoc?id=1afa761d59834c61a30bdf7ffb52a0afaa7d40f4

## Current selected-profile correction (0.1.3)

Terminal-verdict order follows the already frozen `libnftables-json.adoc` VERDICT/REJECT definitions: statements following accept/drop/reject/return/jump/goto are rejected. Reject type values require strings; unknown labels and explicit unmodeled code expressions remain OPEN. This remains a structural input review, with unsupported transfers, protocol applicability, native admission and packet behavior unverified.
