package cvescan

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"regexp"
)

var ErrNotExcute = errors.New("path not excutable")

type RSConfig struct {
	Path_rhsamapcpe string
	Path_rpm2cve    string
	Path_cve2date   string
	Path_RHEL       string
	Path_rpmbin     string
	Path_excludes   []string
}

type ScanReport struct {
	CounterCVE      int
	CounterPkg      int
	CounterHighrisk int

	vulnerable_software map[string][]string
}

type CVEReport struct {
	PkgName  string   `json:"package"`
	FullName string   `json:"fullname"`
	Date     string   `json:"date"`
	CVE      []string `json:"cvelist"`
}

type RPMScanner struct {
	*RSConfig

	//xml
	xmlrpm    STRUCT_Rpms
	rhsaRHEL6 STRUCT_Oval_definitions

	//loaded to memory
	excludeRegExp *regexp.Regexp

	//rpm-to-cve.xml
	rpm2cve   map[string][]string
	xmlrpmver map[string][]string

	distro        string
	distroVersion string
	distroInt     int

	CVE2RHSA           map[string]string
	packagelist        string
	packages_list      map[string]string
	excludePackage     map[string]bool
	packages_nice      map[string]string
	packages_installed []string
	cve2score          map[string]float32
	CVE2DATE           map[string]string

	//for stat
	counter_cve      int
	counter_pkg      int
	counter_highrisk int
	counter_rpm2cve  int
}

func NewRpmScanner(cfg *RSConfig) (*RPMScanner, error) {
	var rs RPMScanner
	rs.RSConfig = cfg
	if cfg.Path_rpmbin != "" {
		st, err := os.Stat(cfg.Path_rpmbin)
		if err != nil {
			return nil, err
		}
		if (st.Mode() & os.ModeExclusive) == 0 {
			return nil, err
		}
		st.Mode().Perm()
	} else {
		path := "/bin/rpm"
	}
	//get os version

	return &rs, nil
}

func (s *RPMScanner) LoadRule() error {
	s.excludePackage = make(map[string]bool)
	excludes := len(s.Path_excludes)
	if excludes != 0 {
		buf := bytes.NewBuffer(nil)
		buf.WriteString("(")
		for idx := 0; idx < excludes; idx++ {
			buf.WriteString(s.Path_excludes[idx])
			if idx > 0 && idx < excludes-1 {
				buf.WriteByte('|')
			}
		}
		buf.WriteString(")")
		s.excludeRegExp = regexp.MustCompile(buf.String())
	}

	var err error
	err = s.loadRpmToCve()
	if err != nil {
		return err
	}
	s.loadRhsa_RHELxXml()
	if err != nil {
		return err
	}

	s.loadCveDate()
	if err != nil {
		return err
	}

	s.loadRhSamapcpe()
	if err != nil {
		return err
	}
	return nil
}

func (s *RPMScanner) ReloadRule() error {
	return s.LoadRule()
}

func (s *RPMScanner) Scan() (ScanReport, error) {
	var rpt ScanReport
	rpt.vulnerable_software = make(map[string][]string)

	err := s.getPackageList()
	if err != nil {
		return rpt, err
	}
	s.doScan(&rpt)
	s.doExport(&rpt)
	s.doSummary()
	return rpt, nil
}