# Current public-audit correction verification — 2026-10-03

Version **0.1.3**: **26 source** and **26 fresh installed unittest cases PASS**. New wheel `nft_ingress_audit-0.1.3-py3-none-any.whl` SHA-256 `f0f4214c2cbe52a312901bf6c279e1b2f6a51dd4a8a48fed838751e7acd0d7cd` matched all runtime bytes and retained notice bytes. Installed console tests reject the original misclassified input, with ordinary supported controls retained. Current record: `PUBLIC_AUDIT_FIX_20261003.json`.

Reproduce with `python -m pip install .`, `python -m unittest discover -s tests -v`, and `python -m pip wheel --no-deps --wheel-dir artifacts .`. Fresh macOS Python 3.14 checks are separate from future exact-commit Linux CI. No remote publication, effective host behavior, whole-upstream equivalence or CVP qualification/approval is asserted here.

The following blocks are historical and preserve their original version, count and artifact hashes. They do not validate 0.1.3.

---

# Current package verification — 2026-10-02

Version **0.1.2**: **17 installed unittest cases PASS**. The rebuilt package records `dhtfish98` as the new implementation author. Runtime files matched source and the separately installed wheel; retained third-party notices were checked.

Wheel: `nft_ingress_audit-0.1.2-py3-none-any.whl`. SHA-256: `4c23a5f5b95711e4d4a135a9fe72d7485ca77f12ab5c6c035666875ba8406b52`. Current result: `ATTRIBUTION_UPDATE_20261002.json`.

Reproduce with `python -m pip install .`, `python -m unittest discover -s tests -v`, and `python -m pip wheel --no-deps --wheel-dir artifacts .`. Local checks exercised macOS Python 3.14; exact-commit GitHub CI records Linux results separately. Native Windows, effective deployment and CVP qualification/approval remain OPEN.

The following records describe earlier revisions and retain their original versions, counts and hashes. They do not validate this new package.

---

# Current re-audit verification — 2026-10-02

Version **0.1.1**: **17 installed unittest cases PASS**. A new wheel was built and installed into a fresh, separate environment. Runtime bytes in source, wheel and installed package matched. Dependency checks and retained license bytes passed.

Wheel: `nft_ingress_audit-0.1.1-py3-none-any.whl`. SHA-256: `d099cfdbc2d705ec9227b5feed915edd8ff5029d526b1d3d1a90189d06df634f`. Current machine-readable result: `REAUDIT_20261002.json`.

Reproduce with `python -m pip install .`, `python -m unittest discover -s tests -v`, and `python -m pip wheel --no-deps --wheel-dir artifacts .`. Python 3.14/macOS was exercised locally. Exact-commit GitHub checks provide separate Linux evidence; native Windows and effective deployment remain OPEN. Project scope and unsupported input behavior remain defined in README.md.

The records below are historical source/oracle/initial-installation evidence, retained for provenance. Earlier test counts, wheel hashes, versions and installation claims refer to the original release and do not validate this repaired release. Full upstream equivalence and CVP applicant qualification/approval remain OPEN.

---

# Validation

PASS: local unit tests, independent wheel build, isolated target install, import origin, and all CLI example exit codes. See `artifacts/validation.json` for commands, results and wheel SHA-256.

This confirms local Python snapshot behavior only. Effective Linux/Windows runtime protection, real-device telemetry, upstream behavioral equivalence, and CVP qualification/approval remain OPEN.
