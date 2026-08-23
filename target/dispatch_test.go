package target

import (
	"testing"

	"github.com/anirudhbiyani/cloud-auth/core"
)

func TestForReturnsExchangerPerCloud(t *testing.T) {
	for _, c := range []core.Cloud{core.AWS, core.GCP, core.Azure} {
		ex, err := For(c)
		if err != nil {
			t.Errorf("For(%s): %v", c, err)
		}
		if ex == nil {
			t.Errorf("For(%s): nil exchanger", c)
		}
	}
	if _, err := For(core.Cloud("oracle")); err == nil {
		t.Error("For(oracle): want error for unsupported target cloud")
	}
}
