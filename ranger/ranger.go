package ranger

import (
	"net/http"
	"fmt"
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

func (s *Service) IsAccessAllowed(username string, usergroups []string, accessType string, location string)(bool) {
	sort.SliceStable(s.Policies, func(i, j int) bool {return s.Policies[i].Id < s.Policies[j].Id})

	log.Printf("Checking policy for user=%s, groups=%s, access=%s, location=%s\n",
		username, usergroups, accessType, location)

	allowed := false
	resource_match := false

	for _, p := range s.Policies {
		// match resource
		for _, v := range p.Resources {
			for _, bucket_name := range v.Values {
				if v.IsRecursive {
					bucket_name += "*"
				}
				if glob.Glob(bucket_name, location) {
					resource_match = true
				}
			}
		}

		log.Printf("Policy id=%d, name=%s, resource_match=%s\n", p.Id, p.Name, resource_match)

		if !resource_match {
			continue
		}

		fmt.Printf("Checking allow policy items=%d\n", len(p.PolicyItems))
		// first check for allow policy
		for _, item := range p.PolicyItems {
			// user first
			for _, user := range item.Users {
				log.Printf("Checking allow policy user=%s\n", user)

				if user == username {
					for _, access := range item.Accesses {
						if access.Type == accessType && access.IsAllowed {
							allowed = true
							break
						}
					}
					break
				}
			}

			// groups
			if !allowed {
				for _, usergroup := range usergroups {
					for _, group := range item.Groups {
						if group == usergroup {
							for _, access := range item.Accesses {
								if access.Type == accessType && access.IsAllowed {
									allowed = true
									break
								}
							}
							break
						}
					}
					if allowed {
						break
					}
				}
			}

			// check exceptions

			// check deny policy
			log.Printf("Checking allow policy items=%d\n", len(p.DenyPolicyItems))

			for _, item := range p.DenyPolicyItems {
				// user first
				for _, user := range item.Users {
					if user == username {
						for _, access := range item.Accesses {
							// is allowed signals denial
							if access.Type == accessType && access.IsAllowed {
								allowed = false
								break
							}
						}
						break
					}
				}
			}

			// groups
			if allowed {
				for _, usergroup := range usergroups {
					for _, group := range item.Groups {
						if group == usergroup {
							for _, access := range item.Accesses {
								if access.Type == accessType && access.IsAllowed {
									allowed = false
									break
								}
							}
							break
						}
					}
					if !allowed {
						break
					}
				}
			}
		}
		// if we got here we had a resource match
		break
	}

	return allowed
}

