package main

import (
	"fmt"
	"time"

	"github.com/chennqqi/cvescan"
)

func main() {
	_, v, _ := cvescan.RpmGetDistro("/bin/rpm")
	res := cvescan.RuleResources{
		&cvescan.Resource{
			Url:  "https://www.redhat.com/security/data/metrics/rhsamapcpe.txt",
			Path: "/tmp/rhsamapcpe.txt",
		},
		&cvescan.Resource{
			Url:  "https://www.redhat.com/security/data/metrics/rpm-to-cve.xml",
			Path: "/tmp/rpm-to-cve.xml",
		},
		&cvescan.Resource{
			Url:  "https://www.redhat.com/security/data/metrics/cve_dates.txt",
			Path: "/tmp/cve_dates.txt",
		},
		&cvescan.Resource{
			Url:  fmt.Sprintf("https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL%d.xml", v),
			Path: "/tmp/com.redhat.rhsa-RHELx.xml",
		},
	}
	if err := res.Valid(); err != nil {
		fmt.Println("res valid err", err)
		return
	}

	cfg := &cvescan.RSConfig{
		Path_rhsamapcpe: res[0].Path,
		Path_rpm2cve:    res[1].Path,
		Path_cve2date:   res[2].Path,
		Path_RHEL:       res[3].Path,
		Path_rpmbin:     "/bin/rpm",
	}
	s, err := cvescan.NewRpmScanner(cfg)
	if err != nil || s == nil {
		fmt.Println("new scanner error", err)
		return
	}
	tsNow := time.Now()
	err = s.LoadRule()
	if err != nil {
		fmt.Println("load rule error", err)
		return
	}
	rpt, err := s.Scan()
	if err != nil {
		fmt.Println("scan error:", err)
	}
	fmt.Println("scan result:")
	fmt.Println("[===============================================]")
	fmt.Printf("Total CVE:%d, PKG:%d, HIGHRISK:%d\n",
		rpt.CounterCVE, rpt.CounterPkg, rpt.CounterHighrisk)
        var idx int
	for pkgName, cves := range rpt.Reports {
            idx++
            for k,c := range cves{
		fmt.Printf("[%d:%d] %s: %s %s @ %s on %f \n", idx, 1+k, pkgName, c.CVE, c.RHSA, c.Date, c.Score)
            }
	}
	fmt.Println("==============================")
	fmt.Println("scan cost:", time.Now().Sub(tsNow))
}
