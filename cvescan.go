package cvescan

import (
	"errors"
	"fmt"
)

var ErrTimeout = errors.New("time out")

type Scanner interface {
	Init() error
	CheckUpdate() (bool, error)
	DoUpdate() error
	Scan() ([]CVEReport, error)
}

type CVEReport struct {
	PkgName  string   `json:"package"`
	FullName string   `json:"fullname"`
	Date     string   `json:"date"`
	CVE      []string `json:"cvelist"`
}

type Config struct {
	CacheDir string `default:"$PWD"`

	ExcludePackages []string

	//rpm for centos&redhat
	RPM           bool
	RPMVer        int
	RPM2CVEUrl    string `default:"https://www.redhat.com/security/data/metrics/rpm-to-cve.xml"`
	RHELUrl       string `default:"https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL6.xml"`
	CVEDateUrl    string `default:"https://www.redhat.com/security/data/metrics/cve_dates.txt"`
	RhSamapcpeUrl string `default:"https://www.redhat.com/security/data/metrics/rhsamapcpe.txt"`
	//dpkg for debian,ubuntu
}

type CVEScanner struct {
	Config
	res []Resource
	rpm *RPMScanner
}

func NewScanner(cfg *Config) (Scanner, error) {
	var s CVEScanner
	if cfg.RPM {
		if cfg.RPMVer == 0 {
			rpm := &RPMScanner{
				path_rhsamapcpe: fmt.Sprintf("%s/rhsamapcpe.txt", cfg.CacheDir),
				path_rpm2cve:    fmt.Sprintf("%s/rpm-to-cve.xml", cfg.CacheDir),
				path_cve2date:   fmt.Sprintf("%s/cve_dates.txt", cfg.CacheDir),
				path_RHEL:       fmt.Sprintf("%s/%s/com.redhat.rhsa-RHEL%d.xml", cfg.RPMVer),
				path_rpmbin:     fmt.Sprintf("/bin/rpm"),
			}
		}
	}

	return nil, errors.New("Not support yet")
}
