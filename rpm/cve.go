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
packagelist  nil
packages_list nil
packages_nice
cve2score
packages_installed
CVE2DATE


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
	publicExp := regexp.MustCompile(`public=\d{8}`)
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		} else {
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
		cmd := exec.Command("/bin/rpm", `--nosignature --nodigest -qf /etc/redhat-release --qf '%{N}-%{V}-%{R}'`)
		//distro = `/bin/rpm --nosignature --nodigest -qf /etc/redhat-release --qf '%{N}-%{V}-%{R}'`
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		fmt.Println("stdout:", stdout.String())
		fmt.Println("stderr:", stderr.String())

		if err != nil {
			fmt.Println("Run cmd err", err)
			return
		}
		distro = stdout.String()
	}

	{ //packagelist
		cmd := exec.Command("/bin/rpm", `--nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}\n'`)
		//packagelist = `/bin/rpm --nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}\n`
		//packagelist = `/bin/rpm --nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}-%{V}-%{R}\n'`
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {

		}
		packagelist = stdout.String()
		packageExp := regexp.MustCompile(`\s+(.*)`)
		/*
			my %packages_list = map  { split(/\s+/, $_, 2) } grep { m/\s+/ } split(/\n/, $packagelist);
		*/
		lines := strings.Split(packagelist, "\n")
		for idx := 0; idx < len(lines); idx++ {
			// {完整项起始, 完整项结束, 子项起始, 子项结束, 子项起始, 子项结束, ...},
			matched := packageExp.FindAllStringSubmatchIndex(lines[idx], 1)
			if len(matched) > 0 {
				pkgFullNameEnd := matched[0][0] //
				pkgFullName := lines[idx][:pkgFullNameEnd]
				pkgNameStart := matched[0][2]
				pkgName := lines[idx][pkgNameStart:]
				pkgFullName = strings.Replace(pkgFullName, ".centos", "", -1)
				packages_list[pkgName] = pkgFullName
			}
		}
	}
	{ //package_nice
		cmd := exec.Command("/bin/rpm", `--nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}\n'`)
		//packagelist = `/bin/rpm --nosignature --nodigest -qa --qf '%{N}-%{epochnum}:%{V}-%{R} %{N}-%{V}-%{R}\n'`
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {

		}
		packageExp := regexp.MustCompile(`\s+(.*)`)
		packagelist = stdout.String()
		/*
			my %packages_list = map  { split(/\s+/, $_, 2) } grep { m/\s+/ } split(/\n/, $packagelist);
		*/
		lines := strings.Split(packagelist, "\n")
		for idx := 0; idx < len(lines); idx++ {
			// {完整项起始, 完整项结束, 子项起始, 子项结束, 子项起始, 子项结束, ...},
			matched := packageExp.FindAllStringSubmatchIndex(lines[idx], 1)
			if len(matched) > 0 {
				pkgFullNameEnd := matched[0][0] //
				pkgFullName := lines[idx][:pkgFullNameEnd]
				pkgNameStart := matched[0][2]
				pkgName := lines[idx][pkgNameStart:]
				pkgFullName = strings.Replace(pkgFullName, ".centos", "", -1)
				packages_nice[pkgName] = pkgFullName
			}
		}
	}
	packages_installed = make([]string, len(packages_nice))
	idx := 0
	for _, name := range packages_nice {
		packages_installed[idx] = strings.Replace(name, ".centos", "", -1)
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

	for idx := 0; idx < len(rhsaRHEL6.Definitions.Definition); idx++ {
		pDef := &rhsaRHEL6.Definitions.Definition[idx]
		for jdx := 0; jdx < len(pDef.Metadata.Advisory.Cve); jdx++ {
			pCve := &pDef.Metadata.Advisory.Cve[jdx]
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
	for pkgName, _ := range packages_list {
		//1. TODO: exclude

		//2. pkgTags[0]->Name pkgTags[1]->version
		pkgTags := strings.Split(pkgName, ":")
		_, exist := xmlrpmver[pkgTags[0]]
		if !exist {
			continue
		}

		//compare from version list
		for _, version := range xmlrpmver[pkgTags[0]] {
			pkgv1 := packages_nice[pkgTags[0]]
			pkgv2 := packages_list[pkgTags[0]] + "-" + version

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

		fmt.Printf("%-40s%-20s\n", cve, score)
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
	cve2Score()
	cve2Date()
	doMatchVulnerable()
	doExport()
}
