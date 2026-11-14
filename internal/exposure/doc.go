// Package exposure is network mode: ASN/CIDR resolution and sweep, banner
// enrichment, leak and datastore checks, KEV/EPSS/NVD feeds, and the CVE join.
// Its results become ordinary findings (see SyncFindings) so the main report,
// retest, tickets and export work on a network block.
//
// Capture stages touch the network and are gated; feed and join stages are
// offline over a workdir, so they can run anywhere.
package exposure
