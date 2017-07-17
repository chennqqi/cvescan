package cvescan

import (
	"testing"
)

func Test_RpmCmp(t *testing.T) {
	dat := []struct {
		A      string
		B      string
		Expect int
	}{
		{
			"perl-Test-Harness-0:3.17-136.el6",
			"perl-Test-Harness-0:3.17-136.el6",
			0,
		},
		{
			"patch-0:2.6-6.el6",
			"patch-0:2.5-6.el6",
			1,
		},
		{
			"xz-lzma-compat-0:3.999.9-0.3.beta.20091007git.el6",
			"xz-lzma-compat-0:4.999.9-0.3.beta.20091007git.el6",
			-1,
		},
	}
	var returned = []string{
		">",
		"=",
		"<",
	}
	for _, v := range dat {
		r := RpmCompare(v.A, v.B)
		if r != v.Expect {
			t.Errorf("%s cmp %s Expect %s, but returned %s",
				v.A, v.B, returned[v.Expect+1], returned[r+1])
			return
		}
	}
}
