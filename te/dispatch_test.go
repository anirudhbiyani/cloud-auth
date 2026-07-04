package te

import (
	"testing"

	"github.com/anirudhbiyani/cloud-auth/cloudauth"
)

func TestForReturnsExchangerPerCloud(t *testing.T) {
	for _, c := range []cloudauth.Cloud{cloudauth.AWS, cloudauth.GCP, cloudauth.Azure} {
		ex, err := For(c)
		if err != nil {
			t.Errorf("For(%s): %v", c, err)
		}
		if ex == nil {
			t.Errorf("For(%s): nil exchanger", c)
		}
	}
	if _, err := For(cloudauth.Cloud("oracle")); err == nil {
		t.Error("For(oracle): want error for unsupported target cloud")
	}
}
