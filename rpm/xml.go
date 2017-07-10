package rpm

import (
	"encoding/xml"
)

type STRUCT_Erratum struct {
	XMLName  xml.Name `xml:" erratum"`
	Released string   `xml:" released,attr"`
	Erratum  string   `xml:"erratum"`
}

type STRUCT_Rpm struct {
	XMLName xml.Name       `xml:" rpm"`
	Erratum STRUCT_Erratum `xml:" erratum"`
	Cve     []string       `xml:" cve"`
	Rpm     string         `xml:" rpm,attr"`
}
type STRUCT_Rpms struct {
	XMLName xml.Name     `xml:" rpms"`
	Rpm     []STRUCT_Rpm `xml:" rpm"`
}

//com.redhat.rhsa-RHEL6.xml
type STRUCT_Bugzilla struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 bugzilla"`
	Href    string   `xml:" href,attr"`
	Id      string   `xml:" id,attr"`
}
type STRUCT_Advisory struct {
	XMLName           xml.Name                 `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 advisory"`
	Issued            STRUCT_Issued            `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 issued"`
	Updated           STRUCT_Updated           `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 updated"`
	Cve               []STRUCT_Cve             `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 cve"`
	Bugzilla          []STRUCT_Bugzilla        `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 bugzilla"`
	Affected_cpe_list STRUCT_Affected_cpe_list `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 affected_cpe_list"`
	Severity          STRUCT_Severity          `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 severity"`
	Rights            STRUCT_Rights            `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 rights"`
	From              string                   `xml:" from,attr"`
}
type STRUCT_Objects struct {
	XMLName        xml.Name                `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 objects"`
	Rpminfo_object []STRUCT_Rpminfo_object `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_object"`
}
type STRUCT_Rpminfo_state struct {
	XMLName xml.Name   `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_state"`
	Evr     STRUCT_Evr `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux evr"`
	Id      string     `xml:" id,attr"`
	Version string     `xml:" version,attr"`
}
type STRUCT_Title struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 title"`
}
type STRUCT_Description struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 description"`
}
type STRUCT_Updated struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 updated"`
	Date    string   `xml:" date,attr"`
}

type STRUCT_Cve struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 cve"`
	Public  string   `xml:" public,attr"`
	Cvss2   string   `xml:" cvss2,attr"`
	Cvss3   string   `xml:" cvss3,attr"`
	Href    string   `xml:" href,attr"`
	CVEID   string   `xml:",chardata"`
}

type STRUCT_Generator struct {
	XMLName         xml.Name               `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 generator"`
	Product_version STRUCT_Product_version `xml:"http://oval.mitre.org/XMLSchema/oval-common-5 product_version"`
	Schema_version  STRUCT_Schema_version  `xml:"http://oval.mitre.org/XMLSchema/oval-common-5 schema_version"`
	Timestamp       STRUCT_Timestamp       `xml:"http://oval.mitre.org/XMLSchema/oval-common-5 timestamp"`
	Content_version STRUCT_Content_version `xml:"http://oval.mitre.org/XMLSchema/oval-common-5 content_version"`
	Product_name    STRUCT_Product_name    `xml:"http://oval.mitre.org/XMLSchema/oval-common-5 product_name"`
}
type STRUCT_State struct {
	XMLName   xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux state"`
	State_ref string   `xml:" state_ref,attr"`
}
type STRUCT_States struct {
	XMLName       xml.Name               `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 states"`
	Rpminfo_state []STRUCT_Rpminfo_state `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_state"`
}
type STRUCT_Platform struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 platform"`
}
type STRUCT_Reference struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 reference"`
	Ref_id  string   `xml:" ref_id,attr"`
	Ref_url string   `xml:" ref_url,attr"`
	Source  string   `xml:" source,attr"`
}
type STRUCT_Severity struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 severity"`
}
type STRUCT_Criterion struct {
	XMLName  xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 criterion"`
	Comment  string   `xml:" comment,attr"`
	Test_ref string   `xml:" test_ref,attr"`
}
type STRUCT_Criteria struct {
	XMLName   xml.Name           `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 criteria"`
	Criterion []STRUCT_Criterion `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 criterion"`
	Criteria  []STRUCT_Criteria  `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 criteria"`
	Operator  string             `xml:" operator,attr"`
}
type STRUCT_Rpminfo_object struct {
	XMLName xml.Name    `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_object"`
	Name    STRUCT_Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux name"`
	Version string      `xml:" version,attr"`
	Id      string      `xml:" id,attr"`
}
type STRUCT_Timestamp struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-common-5 timestamp"`
}
type STRUCT_Rights struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 rights"`
}
type STRUCT_Metadata struct {
	XMLName     xml.Name           `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 metadata"`
	Title       STRUCT_Title       `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 title"`
	Affected    STRUCT_Affected    `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 affected"`
	Reference   []STRUCT_Reference `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 reference"`
	Description STRUCT_Description `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 description"`
	Advisory    STRUCT_Advisory    `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 advisory"`
}
type STRUCT_Rpminfo_test struct {
	XMLName xml.Name      `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_test"`
	Object  STRUCT_Object `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux object"`
	State   STRUCT_State  `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux state"`
	Id      string        `xml:" id,attr"`
	Version string        `xml:" version,attr"`
	Check   string        `xml:" check,attr"`
	Comment string        `xml:" comment,attr"`
}
type STRUCT_Name struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux name"`
}
type STRUCT_Evr struct {
	XMLName   xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux evr"`
	Datatype  string   `xml:" datatype,attr"`
	Operation string   `xml:" operation,attr"`
}
type STRUCT_Product_name struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-common-5 product_name"`
}
type STRUCT_Content_version struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-common-5 content_version"`
}
type STRUCT_Issued struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 issued"`
	Date    string   `xml:" date,attr"`
}
type STRUCT_Oval_definitions struct {
	XMLName        xml.Name           `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 oval_definitions"`
	Objects        STRUCT_Objects     `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 objects"`
	States         STRUCT_States      `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 states"`
	Generator      STRUCT_Generator   `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 generator"`
	Definitions    STRUCT_Definitions `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 definitions"`
	Tests          STRUCT_Tests       `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 tests"`
	Oval           string             `xml:"xmlns oval,attr"`
	Red_Def        string             `xml:"xmlns red-def,attr"`
	Unix_Def       string             `xml:"xmlns unix-def,attr"`
	Xsi            string             `xml:"xmlns xsi,attr"`
	SchemaLocation string             `xml:"http://www.w3.org/2001/XMLSchema-instance schemaLocation,attr"`
	Xmlns          string             `xml:" xmlns,attr"`
}
type STRUCT_Product_version struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-common-5 product_version"`
}
type STRUCT_Schema_version struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-common-5 schema_version"`
}
type STRUCT_Affected struct {
	XMLName  xml.Name          `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 affected"`
	Platform []STRUCT_Platform `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 platform"`
	Family   string            `xml:" family,attr"`
}
type STRUCT_Definition struct {
	XMLName  xml.Name        `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 definition"`
	Criteria STRUCT_Criteria `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 criteria"`
	Metadata STRUCT_Metadata `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 metadata"`
	Version  string          `xml:" version,attr"`
	Class    string          `xml:" class,attr"`
	Id       string          `xml:" id,attr"`
}
type STRUCT_Tests struct {
	XMLName      xml.Name              `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 tests"`
	Rpminfo_test []STRUCT_Rpminfo_test `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux rpminfo_test"`
}
type STRUCT_Cpe struct {
	XMLName xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 cpe"`
}
type STRUCT_Affected_cpe_list struct {
	XMLName xml.Name     `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 affected_cpe_list"`
	Cpe     []STRUCT_Cpe `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 cpe"`
}
type STRUCT_Definitions struct {
	XMLName    xml.Name            `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 definitions"`
	Definition []STRUCT_Definition `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5 definition"`
}
type STRUCT_Object struct {
	XMLName    xml.Name `xml:"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux object"`
	Object_ref string   `xml:" object_ref,attr"`
}
