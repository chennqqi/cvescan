package cvescan

import (
	"errors"
	"time"
)

var ErrTimeout = errors.New("time out")

type CVEScanner interface {
	Init() error
	GetDistro() string
	Scan(timeout time.Duration) ([]CVEReport, error)
}

type CVEReport struct {
	PkgName  string   `json:"package"`
	FullName string   `json:"fullname"`
	CVE      []string `json:"cvelist"`
}

type Config struct {
	CacheDir string `default:"$PWD"`

	RPM2CVEUrl    string `default:"https://www.redhat.com/security/data/metrics/rpm-to-cve.xml"`
	RHELUrl       string `default:"https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL6.xml"`
	CVEDateUrl    string `default:"https://www.redhat.com/security/data/metrics/cve_dates.txt"`
	RhSamapcpeUrl string `default:"https://www.redhat.com/security/data/metrics/rhsamapcpe.txt"`
}

func NewScanner(cfg *Config) (CVEScanner, error) {
	return nil, nil
}
