package main

import (
	"encoding/binary"
	"testing"
)

func TestLoadDefaultCreds(t *testing.T) {
	m, err := loadDefaultCreds()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["_comment"]; ok {
		t.Error("_comment must be stripped")
	}
	for _, svc := range []string{"redis", "elasticsearch", "mysql", "mongodb"} {
		if len(m[svc]) == 0 {
			t.Errorf("no default creds for %s", svc)
		}
	}
	// The classic ES default must be present.
	found := false
	for _, c := range m["elasticsearch"] {
		if c.User == "elastic" && c.Pass == "changeme" {
			found = true
		}
	}
	if !found {
		t.Error("elastic:changeme default must be in the set")
	}
}

func TestMongoFrameLength(t *testing.T) {
	msg := mongoOpMsg(bsonListDatabases())
	if got := binary.LittleEndian.Uint32(msg[0:4]); int(got) != len(msg) {
		t.Fatalf("OP_MSG length field %d != actual %d", got, len(msg))
	}
	if op := binary.LittleEndian.Uint32(msg[12:16]); op != 2013 {
		t.Fatalf("opCode = %d, want 2013 (OP_MSG)", op)
	}
	doc := bsonListDatabases()
	if got := binary.LittleEndian.Uint32(doc[0:4]); int(got) != len(doc) {
		t.Fatalf("BSON length field %d != actual %d", got, len(doc))
	}
}

func TestDBResultCritical(t *testing.T) {
	if !(dbResult{Status: "OPEN-NOAUTH"}).critical() || !(dbResult{Status: "DEFAULT-CRED"}).critical() {
		t.Error("OPEN-NOAUTH and DEFAULT-CRED are critical")
	}
	if (dbResult{Status: "AUTH-ENFORCED"}).critical() {
		t.Error("AUTH-ENFORCED is not critical")
	}
}
