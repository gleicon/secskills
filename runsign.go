package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// Item 5 — Cryptographic run signing.
// A SHA-256 proves integrity only if you trust the hash's source. A signature
// proves origin. We sign the run manifest with an ed25519 key using a minimal
// DSSE-style envelope (payload + signature), so a verifier can assert "this
// assessment was produced by this key and has not been modified."

func keyDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secskills-keys")
}

// loadOrCreateKey returns the signing key, generating a persistent one on first
// use. The public key is written alongside so it can be distributed to verifiers.
func loadOrCreateKey() (ed25519.PrivateKey, error) {
	dir := keyDir()
	os.MkdirAll(dir, 0o700)
	priv := filepath.Join(dir, "ed25519.key")
	if b, err := os.ReadFile(priv); err == nil {
		blk, _ := pem.Decode(b)
		if blk != nil && len(blk.Bytes) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(blk.Bytes), nil
		}
	}
	pub, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "SECSKILLS ED25519 PRIVATE KEY", Bytes: pk}), 0o600)
	os.WriteFile(filepath.Join(dir, "ed25519.pub"), pem.EncodeToMemory(&pem.Block{Type: "SECSKILLS ED25519 PUBLIC KEY", Bytes: pub}), 0o644)
	return pk, nil
}

// DSSEEnvelope is a minimal signing envelope (payloadType + payload + sig).
type DSSEEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`     // base64 of the signed bytes
	PayloadSHA  string `json:"payload_sha256"`
	Sig         string `json:"signature"`   // base64 ed25519 sig
	PublicKey   string `json:"public_key"`  // base64 ed25519 public key
}

// signRunManifest signs run-meta.json into run-attestation.sig (a DSSE envelope).
func signRunManifest(wd string) (string, error) {
	payload, err := os.ReadFile(filepath.Join(wd, "run-meta.json"))
	if err != nil {
		return "", fmt.Errorf("no run-meta.json to sign: %w", err)
	}
	pk, err := loadOrCreateKey()
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(pk, payload)
	sum := sha256.Sum256(payload)
	env := DSSEEnvelope{
		PayloadType: "application/vnd.secskills.run-attestation+json",
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadSHA:  fmt.Sprintf("%x", sum),
		Sig:         base64.StdEncoding.EncodeToString(sig),
		PublicKey:   base64.StdEncoding.EncodeToString(pk.Public().(ed25519.PublicKey)),
	}
	b, _ := json.MarshalIndent(env, "", "  ")
	out := filepath.Join(wd, "run-attestation.sig")
	return out, os.WriteFile(out, b, 0o644)
}

// verifyRunManifest verifies a DSSE envelope against its embedded public key and
// the current run-meta.json.
func verifyRunManifest(wd string) error {
	b, err := os.ReadFile(filepath.Join(wd, "run-attestation.sig"))
	if err != nil {
		return fmt.Errorf("no signature envelope: %w", err)
	}
	var env DSSEEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(env.PublicKey)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return fmt.Errorf("SIGNATURE INVALID — payload does not match signature")
	}
	// also confirm the envelope payload still matches the on-disk manifest
	cur, _ := os.ReadFile(filepath.Join(wd, "run-meta.json"))
	if fmt.Sprintf("%x", sha256.Sum256(cur)) != env.PayloadSHA {
		return fmt.Errorf("SIGNATURE VALID but run-meta.json has changed since signing")
	}
	return nil
}

// cmdAttest signs or verifies a run's attestation envelope.
func cmdAttest(args []string) error {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	sign := fs.String("sign", "", "target: sign its latest run attestation")
	verify := fs.String("verify", "", "target: verify its run attestation signature")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *sign != "":
		out, err := signRunManifest(workdir(*sign))
		if err != nil {
			return err
		}
		fmt.Printf("signed: %s\n", out)
		return nil
	case *verify != "":
		if err := verifyRunManifest(workdir(*verify)); err != nil {
			return err
		}
		fmt.Println("signature OK — run attestation is authentic and unmodified")
		return nil
	}
	return fmt.Errorf("usage: secskills attest --sign <target> | --verify <target>")
}
