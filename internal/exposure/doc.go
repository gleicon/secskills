// Package exposure is the ASN/CIDR exposure pipeline: prefix resolution and
// sweep, banner enrichment, leak and datastore checks, KEV/EPSS/NVD feeds, the
// CVE join, finding lifecycle, precision gate, tenant delivery, notification
// latency, fleet aggregation and the prefix report.
//
// Capture stages touch the network and are gated; feed and join stages are
// offline over a workdir, so they can run anywhere.
package exposure
