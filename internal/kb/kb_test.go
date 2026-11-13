package kb

import (
	"testing"

	"github.com/gleicon/secskills/internal/textutil"
)

func TestKBClasses(t *testing.T) {
	classes := KBClasses()
	if len(classes) < 9 {
		t.Fatalf("expected >=9 KB classes, got %d", len(classes))
	}
	if !textutil.Contains(classes, "injection") || !textutil.Contains(classes, "top10") {
		t.Error("KB missing injection/top10 classes")
	}
	if _, err := KBClassText("injection"); err != nil {
		t.Errorf("kbClassText(injection): %v", err)
	}
}
