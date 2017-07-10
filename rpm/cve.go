package rpm

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/infogulch/uniq"
)

const rhsamapcpe = "rhsamapcpe.txt"

var hostname string

var xmlrpm STRUCT_Rpms
var rhsaRHEL6 STRUCT_Oval_definitions
var xmlrhsa string

//for stat
var counter_cve int
var counter_pkg int
var counter_highrisk int

type RHSA2CVE map[string]string

/*
rpm2cve	OK
packagelist
packages_list
packages_nice
cve2score					nil
packages_installed
CVE2DATE					nil


*/

//
var rpm2cve map[string][]string
var xmlrpmver map[string][]string
var counter_rpm2cve int

//
var CVE2RHSA RHSA2CVE
var distro string
var packagelist string
var packages_list map[string]string
var excludePackage map[string]string
var packages_nice map[string]string
var vulnerable_software map[string][]string
var packages_installed []string
var cve2score map[string]float32
var CVE2DATE map[string]string

func init() {
	hostname, _ = os.Hostname()
	CVE2RHSA = make(RHSA2CVE)
	xmlrpmver = make(map[string][]string)
	rpm2cve = make(map[string][]string)
	packages_list = make(map[string]string)
	excludePackage = make(map[string]string)
	vulnerable_software = make(map[string][]string)
	CVE2DATE = make(map[string]string)
	packages_nice = make(map[string]string)
	cve2score = make(map[string]float32)
}

func loadRhSamapcpe() error {
	f, err := os.Open(rhsamapcpe)
	if err != nil {
		return nil
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			break
		}
		trimLine := strings.TrimRight(string(line), "\n")
		elements := strings.Split(trimLine, " ")
		if len(elements) < 2 {
			fmt.Println(len(elements), trimLine)
			continue
		}

		cvelines := strings.Replace(elements[1], "CAN-", "CVE-", -1)
		cves := strings.Split(cvelines, ",")
		for _, cve := range cves {
			CVE2RHSA[cve] += elements[0] + " "
		}
	}
	return nil
}

//"rpm-to-cve.xml"
func loadRpmToCve(xmlFile string) error {
	txt, err := ioutil.ReadFile(xmlFile)
	if err != nil {
		return err
	}
	return xml.Unmarshal(txt, &xmlrpm)
}

func rpm2Cve() {
	var pRpm *STRUCT_Rpm
	for idx := 0; idx < len(xmlrpm.Rpm); idx++ {
		pRpm = &xmlrpm.Rpm[idx]
		if pRpm.Rpm == "" {
			continue
		}
		rpmName := pRpm.Rpm

		counter_rpm2cve++
		if strings.Contains(pRpm.Rpm, "el7") {
			continue
		}

		var advisory []string
		if len(pRpm.Cve) > 0 {
			sort.Strings(pRpm.Cve)
			advisory = pRpm.Cve
			//TODO: BUGS ...
			//rpm2cve[rpmName] = append(rpm2cve[rpmName], advisory)
		} else if pRpm.Erratum.Erratum != "" {
			//push (@advisory, $entry->{erratum}->{content});
			advisory = append(advisory, pRpm.Erratum.Erratum)
		}

		if len(advisory) > 0 {
			rpm2cve[rpmName] = append(rpm2cve[rpmName], advisory...)
		}

		rpmV := strings.SplitN(pRpm.Rpm, ":", 2)
		rpmne := rpmV[0]
		rpmvr := rpmV[1]

		xmlrpmver[rpmne] = append(xmlrpmver[rpmne], rpmvr)
		rawArray := xmlrpmver[rpmne]
		sort.Strings(rawArray)
		uniqIdx := uniq.Strings(rawArray)
		xmlrpmver[rpmne] = rawArray[:uniqIdx]
	}
}

func cve2Date() error {
	f, err := os.Open("cve_dates.txt")
	if err != nil {
		return err
	}
	defer f.Close()

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
				CVE2DATE[cve] = pubs[0][1]
			}
		}
	}
	return nil
}

func getPackageList() {
	{ //distro
		cmd := exec.Command("/bin/rpm", `--nosignature`, `--nodigest`, `-qf`, `/etc/redhat-release`, `--qf`, `'%{N}-%{V}-%{R}'`)
		//distro = `/bin/rpm --nosignature --nodigest -qf /etc/redhat-release --qf '%{N}-%{V}-%{R}'`
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		//		fmt.Println("stdout:", stdout.String())
		//		fmt.Println("stderr:", stderr.String())

		if err != nil {
			fmt.Println("Run cmd err", err)
			return
		}
		distro = stdout.String()
	}

	{ //packagelist
		cmd := exec.Command("/bin/rpm", `--nosignature`, `--nodigest`, `-qa`, `--qf`, `'%{N}-%{epochnum}:%{V}-%{R} %{N}\n'`)
		//packagelist = `/bin/rpm --nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}\n`
		//packagelist = `/bin/rpm --nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}-%{V}-%{R}\n'`
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			fmt.Println("Run cmd err", err)
			return
		}
		//		fmt.Println("stdout:", stdout.String())
		//		fmt.Println("stderr:", stderr.String())
		packagelist = stdout.String()
		packageExp := regexp.MustCompile(`\s+(.*)`)
		/*
			my %packages_list = map  { split(/\s+/, $_, 2) } grep { m/\s+/ } split(/\n/, $packagelist);
		*/
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
				packages_list[pkgFullName] = pkgName
			}
		}
	}
	{ //packages_nice
		cmd := exec.Command("/bin/rpm", `--nosignature`, `--nodigest`, `-qa`, `--qf`, `'%{N}-%{epochnum}:%{V}-%{R} %{N}-%{V}-%{R}\n'`)
		//packagelist = `/bin/rpm --nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}-%{V}-%{R}\n'`
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			fmt.Println("Run cmd err", err)
			return
		}
		packageExp := regexp.MustCompile(`\s+(.*)`)
		packagelist = stdout.String()
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
				packages_nice[pkgFullName] = pkgName
			}
		}
	}
	packages_installed = make([]string, len(packages_nice))
	idx := 0
	for pkgFullName, _:= range packages_nice {
		packages_installed[idx] = strings.Replace(pkgFullName, ".centos", "", -1)
		sort.Strings(packages_installed)
		idx++
	}
}

func loadRhsa_RHEL6Xml() error {
	f, err := os.Open("com.redhat.rhsa-RHEL6.xml")
	if err != nil {
		return err
	}
	defer f.Close()

	buf := bufio.NewReader(f)
	d := xml.NewDecoder(buf)
	return d.Decode(&rhsaRHEL6)
}

func cve2Score() {
	scoreExp := regexp.MustCompile(`(\d+(\.\d+)?)`)
	//    fmt.Println("rhsaRHEL6", rhsaRHEL6)
	for idx := 0; idx < len(rhsaRHEL6.Definitions.Definition); idx++ {
		pDef := &rhsaRHEL6.Definitions.Definition[idx]
		for jdx := 0; jdx < len(pDef.Metadata.Advisory.Cve); jdx++ {
			pCve := &pDef.Metadata.Advisory.Cve[jdx]
			//    fmt.Println("*pCVE:", *pCve)
			if pCve.Cvss2 != "" {
				cveID := pCve.CVEID
				scoreID := pCve.Cvss2
				scores := scoreExp.FindAllStringSubmatch(scoreID, 1)
				var score float32
				fmt.Sscanf(scores[0][1], "%f", &score)
				cve2score[cveID] = score
			}
		}
	}
}

func doMatchVulnerable() {
	for _, pkg := range packages_installed {
		//1. TODO: exclude

		//2. pkgTags[0]->Name pkgTags[1]->version
		pkgTags := strings.Split(pkg, ":")
		if len(pkgTags) < 1 {
			continue
		}
		pkgTag := pkgTags[0]
		versions, exist := xmlrpmver[pkgTag]
		if !exist {
			continue
		}

		//compare from version list
		for _, version := range versions {

            fmt.Println("pkgTag", pkgTag)

			pkgv1, exist1 := packages_nice[pkg]
            pkgv2, exist2 := packages_list[pkg]
			pkgv2 += "-" + version
            if !exist1 || !exist2{
                continue
            }
			fmt.Println("pkgv1", pkgv1)
			fmt.Println("pkgv2", pkgv2)
			switch RpmCompare(pkgv1, pkgv2) {
			case 1:
				counter_pkg++
				newver := pkgTags[0] + ":" + version
				vuls, exist := rpm2cve[newver]
				if exist {
					for _, cve := range vuls {
						vulnerable_software[pkgv1] = append(vulnerable_software[pkgv1], cve)
					}
				}

			case 0:
			case -1:
			default:
			}
		}
	}
}

func doExport() {
	var report struct {
		DATE string
		RHSA string
		PKG  string
		NAME string
	}
	for cve, _ := range vulnerable_software {
		sort.Strings(vulnerable_software[cve])
		var score float32
		if s, exist := cve2score[cve]; exist {
			score = s
		}
		var rhsa = "RHSA N/A"
		if s, exist := CVE2RHSA[cve]; exist {
			rhsa = s
			/* TODO: s/\s+$// */
			//rhsa = //
		}
		report.RHSA = rhsa

		var date = "DATE N/A"
		if _, exist := CVE2DATE[cve]; exist {
			date = CVE2DATE[cve]
		}
		report.DATE = date

		fmt.Printf("%s %f %s\n", cve, score, date)
		counter_cve++
		if score >= 7.0 {
			counter_highrisk++
		}
	}
}

func doSummary() {
	fmt.Println("TOTAL_UNIQ_PACKAGES=", len(packages_installed),
		", AFFECTED_PACKAGES=", counter_pkg,
		" CVEs=", counter_cve, " HIGHRISK=", counter_highrisk)
}

func DoRpmCVEScan() {
	loadRhSamapcpe()
	loadRpmToCve("rpm-to-cve.xml")
	rpm2Cve()
	getPackageList()
	loadRhsa_RHEL6Xml()
	cve2Score()
	cve2Date()
	doMatchVulnerable()

	//fmt.Println("xmlrpmver:", xmlrpmver)
	//	fmt.Println("CVE2RHSA:", CVE2RHSA)
	//	fmt.Println("packagelist", packagelist)
	//	fmt.Println("packages_list:", packages_list)
//		fmt.Println("packages_nice:", packages_nice)
	//	fmt.Println("cve2score:", cve2score)
//		fmt.Println("packages_installed:", packages_installed)
	fmt.Println("VULS:", vulnerable_software)
	//	fmt.Println("CVE2DATE:", CVE2DATE)

	doExport()
}
