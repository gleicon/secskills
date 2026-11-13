# Fixture: exposure pipeline (golden CLI tests)

Offline inputs for the exposure-mode commands (`cvematch`, `lifecycle`,
`prefix-report`, `precision`, `deliver`, `notify`, `fleet`, `token`, `plan`).
All addresses are documentation ranges (RFC 5737 / RFC 5398). `feed/epss.json`
is copied to `epss-<today>.json` by the test so no EPSS lookup leaves the box.
