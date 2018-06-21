package ranger

import (
	"net/http"
	"io/ioutil"
	"encoding/json"
	"sort"
	"github.com/ryanuber/go-glob"
	"log"
)

const (
	policyEndpoint = "/service/plugins/policies/download/"
	policySecureEndpoint = "/service/plugins/secure/policies/download/"
	pluginId = "pluginId"
)

type ResourceData struct {
	Values []string
	IsExcludes bool
	IsRecursive bool
	level int // non json
}

type Access struct {
	Type string
	IsAllowed bool
}

type PolicyItem struct {
	Accesses []Access
	Users []string
	Groups []string
	Conditions []string
	DelegateAdmin bool
}

type Policy struct {
	Id int
	Guid string
	IsEnabled bool
	Version int
	Service string
	Name string
	PolicyType int
	Description string
	IsAuditEnabled bool
	Resources map[string]ResourceData
	PolicyItems []PolicyItem
	DenyPolicyItems []PolicyItem
	AllowExceptions []PolicyItem
	DenyExceptions []PolicyItem
	DataMaskPolicyItems []PolicyItem
	RowFilterPolicyItems []PolicyItem
	PolicyLabels []string
}

type ServiceOptions struct {
	EnableDenyAndExceptionsInPolicies string
}

type ServiceConfig struct {
	ItemId int
	Name string
	Type string
	SubType string
	Mandatory bool
	ValidationRegEx string
	ValidationMessage string
	UiHint string
	Label string
}

type MatcherOptions struct {
	Wildcard string
	IgnoreCase string
}

type AccessTypes struct {
	ItemId int
	Name string
	Label string
	ImpliedGrants []string
}

type ServiceResource struct {
	ItemId int
	Name string
	Type string
	Level int
	Mandatory bool
	LookupSupported bool
	RecursiveSupported bool
	ExcludesSupported bool
	Matcher string
	MatcherOptions MatcherOptions
	ValidationRegEx string
	ValidationMessage string
	UiHint string
	Label string
	Description string
	AccessTypeRestrictions []string
	IsValidLeaf bool
}

type RowFilterDef struct {
	AccessTypes []AccessTypes
	Resources []ResourceData
}

type DataMaskDef struct {
	MaskTypes []string
	AccessTypes []string
	Resources []string
}

type ServiceDefinition struct {
	Id int
	Guid string
	IsEnabled bool
	CreatedBy string
	UpdatedBy string
	CreateTime int64
	UpdateTime int64
	Version int
	Name string
	ImplClass string
	Label string
	Description string
	Options ServiceOptions
	Configs []ServiceConfig
	Resources []ServiceResource
	AccessTypes []AccessTypes
	PolicyConditions []string
	ContextEnrichers []string
	Enums []string
	DataMaskDef DataMaskDef
	RowFilterDef RowFilterDef
	AuditMode string
}

type Service struct {
	ServiceName string
	ServiceId int
	PolicyVersion int
	PolicyUpdateTime int64
	Policies []Policy
	ServiceDef ServiceDefinition
}

type AccessRequest interface {

}

const (
	POLICY_TYPE_ACCESS = 0
	POLICY_TYPE_DATAMASK = 1
	POLICY_TYPE_ROWFILTER = 2
)

func GetPolicy(serviceName string, baseUrl string) (*Service, error) {
	client := http.Client{}
	req, err := http.NewRequest("GET", baseUrl + policyEndpoint + serviceName, nil)

	if err != nil {
		log.Fatal("Request to Apache Ranger failed", err)
		return nil, err
	}

	params := req.URL.Query()
	params.Add(pluginId, serviceName + string("@bla"))

	req.URL.RawQuery = params.Encode()
	resp, err := client.Do(req)

	if err != nil {
		log.Fatal("Request to Apache Ranger failed", err)
		return nil, err
	}

	data, _ := ioutil.ReadAll(resp.Body)

	var service Service

	err = json.Unmarshal(data, &service)

	if err != nil {
		log.Fatal("Could not unmarshal json data", err)
		return nil, err
	}

	return &service, nil
}

func hasAccess(names []string, other []string, accesses []Access, accessType string)(bool) {
	for _, name := range names {
		for i := range other {
			if name == other[i] {
				for _, access := range accesses {
					if access.Type == accessType && access.IsAllowed {
						return true
					}
				}
			}
		}
	}

	return false
}

func (s *Service) IsAccessAllowed(username string, usergroups []string, accessType string, location string)(bool) {
	// TODO: Sort on importance of policy
	sort.SliceStable(s.Policies, func(i, j int) bool {return s.Policies[i].Id < s.Policies[j].Id})

	log.Printf("Checking policy for user=%s, groups=%s, access=%s, location=%s\n",
		username, usergroups, accessType, location)

	allowed := false
	resourceMatch := false

	for _, p := range s.Policies {
		// match resource
		for _, v := range p.Resources {
			for _, bucketName := range v.Values {
				if v.IsRecursive {
					bucketName += "*"
				}
				if glob.Glob(bucketName, location) {
					resourceMatch = true
				}
			}
		}

		log.Printf("Policy id=%d, name=%s, resource_match=%s\n", p.Id, p.Name, resourceMatch)

		if !resourceMatch {
			continue
		}

		// We have a resource match

		log.Printf("Checking allow policy items=%d\n", len(p.PolicyItems))
		for _, item := range p.PolicyItems {
			// user first
			allowed = hasAccess([]string{username}, item.Users, item.Accesses, accessType)

			// groups
			if !allowed {
				allowed = hasAccess(usergroups, item.Groups, item.Accesses, accessType)
			}

			// TODO: check exceptions
		}

		log.Printf("Checking deny policy items=%d\n", len(p.DenyPolicyItems))

		for _, item := range p.DenyPolicyItems {
			// allowed signals denial
			allowed = !hasAccess([]string{username}, item.Users, item.Accesses, accessType)

			// groups
			if allowed {
				allowed = !hasAccess(usergroups, item.Groups, item.Accesses, accessType)
			}

			// TODO: check exceptions
		}

		// if we got here we had a resource match
		break
	}

	return allowed
}

