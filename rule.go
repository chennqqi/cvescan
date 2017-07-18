package cvescan

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/infogulch/uniq"
)

func (s *RPMScanner) loadRpmToCve() error {
	f, err := os.Open(s.Path_rpm2cve)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := bufio.NewReader(f)
	d := xml.NewDecoder(buf)
	err = d.Decode(&s.xmlrpm)
	if err != nil {
		return err
	}

	s.xmlrpmver = make(map[string][]string)
	s.rpm2cve = make(map[string][]string)

	var pRpm *STRUCT_Rpm
	for idx := 0; idx < len(s.xmlrpm.Rpm); idx++ {
		pRpm = &s.xmlrpm.Rpm[idx]
		if pRpm.Rpm == "" {
			continue
		}
		rpmName := pRpm.Rpm

		s.counter_rpm2cve++

		//only handle `this` distroVersion
		if !strings.Contains(pRpm.Rpm, s.distroVersion) {
			continue
		}

		var advisory []string
		if len(pRpm.Cve) > 0 {
			sort.Strings(pRpm.Cve)
			advisory = pRpm.Cve
			//rpm2cve[rpmName] = append(rpm2cve[rpmName], advisory...)
		} else if pRpm.Erratum.Erratum != "" {
			// as it turns out there are 211 entries with no CVE but have RHSA

			//push (@advisory, $entry->{erratum}->{content});
			advisory = append(advisory, pRpm.Erratum.Erratum)
		}
		if len(advisory) > 0 {
			s.rpm2cve[rpmName] = append(s.rpm2cve[rpmName], advisory...)
		}

		rpmV := strings.SplitN(pRpm.Rpm, ":", 2)
		rpmne := rpmV[0]
		rpmvr := rpmV[1]

		s.xmlrpmver[rpmne] = append(s.xmlrpmver[rpmne], rpmvr)
		rawArray := s.xmlrpmver[rpmne]
		sort.Strings(rawArray)
		uniqIdx := uniq.Strings(rawArray)
		s.xmlrpmver[rpmne] = rawArray[:uniqIdx]
	}
	return nil
}

func RpmGetDistro(rpmPath string) (string, int, error) {
	var distro string
	{ //distro
		cmd := exec.Command(rpmPath, `--nosignature`, `--nodigest`, `-qf`, `/etc/redhat-release`, `--qf`, `'%{N}-%{V}-%{R}'`)
		//distro = `/bin/rpm --nosignature --nodigest -qf /etc/redhat-release --qf '%{N}-%{V}-%{R}'`
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			return "", 6, err
		}
		distro = stdout.String()
	}
	if strings.Contains(distro, ".el7") {
		return distro, 7, nil
	} else if strings.Contains(distro, ".el6") {
		return distro, 6, nil
	} else if strings.Contains(distro, ".el5") {
		return distro, 5, nil
	}
	//treat as centos 6
	return distro, 6, errors.New("unknown distro version")
}

func (s *RPMScanner) loadRhSamapcpe() error {
	f, err := os.Open(s.Path_rhsamapcpe)
	if err != nil {
		return nil
	}
	defer f.Close()

	s.CVE2RHSA = make(map[string]string)

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println("loadRhSamapcpe", err)
			return err
		}
		trimLine := strings.TrimRight(string(line), "\n")
		elements := strings.Split(trimLine, " ")
		if len(elements) < 2 {
			//fmt.Println(len(elements), trimLine)
			continue
		}

		cvelines := strings.Replace(elements[1], "CAN-", "CVE-", -1)
		cves := strings.Split(cvelines, ",")
		for _, cve := range cves {
			s.CVE2RHSA[cve] += elements[0] + " "
		}
	}
	return nil
}

func (s *RPMScanner) loadCveDate() error {
	f, err := os.Open(s.Path_cve2date)
	if err != nil {
		return err
	}
	defer f.Close()

	s.CVE2DATE = make(map[string]string)
	reader := bufio.NewReader(f)
	lineExp := regexp.MustCompile(`^(CVE-\d{4}-\d+\S*)\s*(.*)`)
	publicExp := regexp.MustCompile(`public=(\d{8})`)
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println(err)
			return err
		}
		v := lineExp.FindAllStringSubmatch(string(line), 1)
		if len(v) > 0 {
			cve := v[0][1]
			dat := v[0][2]
			pubs := publicExp.FindAllStringSubmatch(dat, 1)
			if len(pubs) > 0 {
				s.CVE2DATE[cve] = pubs[0][1]
			}
		}
	}
	return nil
}

func (s *RPMScanner) getPackageList() error {
	s.packages_list = make(map[string]string)
	s.packages_nice = make(map[string]string)

	{ //packagelist
		cmd := exec.Command(s.Path_rpmbin, `--nosignature`, `--nodigest`, `-qa`, `--qf`, `'%{N}-%{epochnum}:%{V}-%{R} %{N}\n'`)
		//packagelist = `/bin/rpm --nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}\n`
		//packagelist = `/bin/rpm --nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}-%{V}-%{R}\n'`
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			fmt.Println("Run cmd err", err)
			return err
		}
		//fmt.Println("stdout:", stdout.String())
		//fmt.Println("stderr:", stderr.String())
		packagelist := stdout.String()
		packageExp := regexp.MustCompile(`\s+(.*)`)
		//LINE: ''libselinux-utils-0:2.0.94-5.8.el6 libselinux-utils
		lines := strings.Split(packagelist, "\n")
		for idx := 0; idx < len(lines); idx++ {
			// {完整项起始, 完整项结束, 子项起始, 子项结束, 子项起始, 子项结束, ...},
			lineString := strings.TrimLeft(lines[idx], `'`)
			matched := packageExp.FindAllStringSubmatchIndex(lineString, 1)
			if len(matched) > 0 {
				pkgFullNameEnd := matched[0][0] //
				pkgFullName := lineString[:pkgFullNameEnd]
				pkgNameStart := matched[0][2]
				pkgName := lineString[pkgNameStart:]
				pkgFullName = strings.Replace(pkgFullName, ".centos", "", -1)
				s.packages_list[pkgFullName] = pkgName
			}
		}
	}
	{ //packages_nice
		cmd := exec.Command(s.Path_rpmbin, `--nosignature`, `--nodigest`, `-qa`, `--qf`, `'%{N}-%{epochnum}:%{V}-%{R} %{N}-%{V}-%{R}\n'`)
		//packagelist = `/bin/rpm --nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}-%{V}-%{R}\n'`
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			fmt.Println("Run cmd err", err)
			return err
		}
		packageExp := regexp.MustCompile(`\s+(.*)`)
		packagelist := stdout.String()
		/*
			my %packages_list = map  { split(/\s+/, $_, 2) } grep { m/\s+/ } split(/\n/, $packagelist);
		*/
		lines := strings.Split(packagelist, "\n")
		for idx := 0; idx < len(lines); idx++ {
			// {完整项起始, 完整项结束, 子项起始, 子项结束, 子项起始, 子项结束, ...},
			lineString := strings.TrimLeft(lines[idx], `'`)
			matched := packageExp.FindAllStringSubmatchIndex(lineString, 1)
			if len(matched) > 0 {
				pkgFullNameEnd := matched[0][0] //
				pkgFullName := lineString[:pkgFullNameEnd]
				pkgNameStart := matched[0][2]
				pkgName := lineString[pkgNameStart:]
				pkgFullName = strings.Replace(pkgFullName, ".centos", "", -1)
				//                fmt.Println("linestring", lineString)
				//                fmt.Println(matched)
				//               panic(nil)
				s.packages_nice[pkgFullName] = pkgName
			}
		}
	}
	s.packages_installed = make([]string, len(s.packages_nice))
	idx := 0
	for pkgFullName, _ := range s.packages_nice {
		s.packages_installed[idx] = strings.Replace(pkgFullName, ".centos", "", -1)
		sort.Strings(s.packages_installed)
		idx++
	}
	return nil
}

func (s *RPMScanner) loadRhsa_RHELxXml() error {
	f, err := os.Open(s.Path_RHEL)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := bufio.NewReader(f)
	d := xml.NewDecoder(buf)
	err = d.Decode(&s.rhsaRHEL6)
	if err != nil {
		fmt.Println("loadRhsa_RHELxXml", err)
		return err
	}

	s.cve2score = make(map[string]float32)
	scoreExp := regexp.MustCompile(`(\d+(\.\d+)?)`)
	//    fmt.Println("rhsaRHEL6", rhsaRHEL6)
	for idx := 0; idx < len(s.rhsaRHEL6.Definitions.Definition); idx++ {
		pDef := &s.rhsaRHEL6.Definitions.Definition[idx]
		for jdx := 0; jdx < len(pDef.Metadata.Advisory.Cve); jdx++ {
			pCve := &pDef.Metadata.Advisory.Cve[jdx]
			//    fmt.Println("*pCVE:", *pCve)
			if pCve.Cvss2 != "" {
				cveID := pCve.CVEID
				scoreID := pCve.Cvss2
				scores := scoreExp.FindAllStringSubmatch(scoreID, 1)
				var score float32
				fmt.Sscanf(scores[0][1], "%f", &score)
				s.cve2score[cveID] = score
			}
		}
	}
	return nil
}

func (s *RPMScanner) doScan(rpt *ScanReport) {
	var excludePkgFunc func(string) bool
	if s.excludeRegExp != nil {
		excludePkgFunc = s.excludeRegExp.MatchString
	} else {
		excludePkgFunc = func(pkg string) bool {
			return false
		}
	}

	for _, pkg := range s.packages_installed {
		//1. exclude
		if excludePkgFunc(pkg) {
			continue
		}

		//2. pkgTags[0]->Name pkgTags[1]->version
		pkgTags := strings.Split(pkg, ":")
		if len(pkgTags) < 1 {
			continue
		}
		pkgTag := pkgTags[0]
		versions, exist := s.xmlrpmver[pkgTag]
		if !exist {
			continue
		}

		//compare from version list
		for _, version := range versions {
			pkgv1, exist1 := s.packages_nice[pkg]
			pkgv2, exist2 := s.packages_list[pkg]
			pkgv2 += "-" + version
			if !exist1 || !exist2 {
				continue
			}

			//fmt.Println("pkgv1", pkgv1)
			//fmt.Println("pkgv2", pkgv2)
			switch RpmCompare(pkgv1, pkgv2) {
			case 1:
				rpt.CounterPkg++
				newver := pkgTags[0] + ":" + version
				vuls, exist := s.rpm2cve[newver]
				if exist {
					for _, cve := range vuls {
						rpt.vulnerable_software[pkgv1] = append(rpt.vulnerable_software[pkgv1], cve)
					}
				}

			case 0:
			case -1:
			default:
			}
		}
	}
}

func (s *RPMScanner) doExport(rpt *ScanReport) {
	var report CVEReport
	for cve, _ := range rpt.vulnerable_software {
		sort.Strings(rpt.vulnerable_software[cve])
		var score float32
		if s, exist := s.cve2score[cve]; exist {
			score = s
		}
		var rhsa = "RHSA N/A"
		if s, exist := s.CVE2RHSA[cve]; exist {
			rhsa = s
			/* TODO: s/\s+$// */
			//rhsa = //
		}
		report.RHSA = rhsa

		var date = "DATE N/A"
		if _, exist := s.CVE2DATE[cve]; exist {
			date = s.CVE2DATE[cve]
		}
		report.Date = date
		report.Score = score
		rpt.Reports = append(rpt.Reports, report)

		rpt.CounterCVE++
		if score >= 7.0 {
			rpt.CounterHighrisk++
		}
	}
}
