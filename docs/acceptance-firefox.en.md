[简体中文](acceptance-firefox.md) | [繁體中文](acceptance-firefox.zh-TW.md) | [English](acceptance-firefox.en.md)

# Firefox Exclusion Notice (First GA)

> **This is not a first-GA acceptance checklist and cannot produce a Firefox PASS.**

The first GA ships only the Chromium ZIP shared by Chrome and Edge. Firefox retains `manifest.firefox.json` and related source solely as a future development starting point. It is not packaged, temporarily loaded for release acceptance, submitted to the Firefox store, or included in `scripts/release-gate.sh --strict`.

## Scope guards that must hold now

- `apps/extension-chromium/scripts/package-store.sh --firefox` exits nonzero and creates no Firefox ZIP;
- the Chrome / Edge ZIP contains no `manifest.firefox.json`, Native host, or Firefox-specific metadata;
- first-GA README, store copy, permission disclosure, acceptance reports, and release decisions never claim Firefox support;
- historical F1–F8 reports, Firefox screenshots, `AGENTGUARD_ACCEPTANCE_FIREFOX=PASS`, and `acceptance_firefox` JSON cannot authorize a first-GA release.

The only current executable check is a negative scope check:

```bash
make check-extension-gate
apps/extension-chromium/scripts/package-store.sh --firefox
# Expected: exit 64 and no Firefox package.
```

Failure of the second command is the expected scope-guard behavior; it produces no Firefox product PASS.

## Legacy CLI capability

`guard-cli manual-acceptance firefox`, `evidence-template --kind acceptance_firefox`, and the corresponding validation code remain temporarily for legacy/future format compatibility. The strict gate does not read `AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX` and does not accept that kind as first-GA evidence. A success marker from a direct legacy invocation proves only that the legacy format validated; it cannot change product scope.

## Preconditions for any future Firefox release

A new Firefox release checklist may be created only after a separate product decision. At minimum it requires:

1. a fresh review of the Firefox manifest, permissions, and store privacy disclosure;
2. an independent reproducible Firefox packaging path whose conclusion is not inherited from the Chromium ZIP;
3. real-Firefox testing of DOM, Shadow DOM, frames, DNR methods/encodings/resource types, and false-positive boundaries;
4. Firefox-specific fresh-install, upgrade, uninstall, rollback, and store-candidate identity evidence;
5. a separate permission, identity, privacy, and migration design if Native Messaging is ever reconsidered, rather than inheriting the old prototype;
6. an explicit Firefox evidence kind, strict-gate wiring, and trilingual release documentation before changing the support matrix.

Until every condition is complete, Firefox status is fixed as: **source prototype / outside first GA / no release PASS**.
