# Fixture: network block (golden CLI tests)

Offline inputs for the network-block commands (`cvematch`, `plan`) and the
reports they feed. `workdir/` is copied to the workdir of `203.0.113.0/24`;
`feed/` is the KEV/NVD cache. All addresses are documentation ranges (RFC 5737 /
RFC 5398). `feed/epss.json` is copied to `epss-<today>.json` by the test so no
EPSS lookup leaves the box.
