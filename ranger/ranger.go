package ranger

import (
	"net/http"
	"io/ioutil"
	"encoding/json"
	"sort"
	"github.com/ryanuber/go-glob"
	"log"
	"math"
	"time"
	"errors"
	"net"
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

type Condition struct {
	Type string
	Values []string
}

type PolicyItem struct {
	Accesses []Access
	Users []string
	Groups []string
	Conditions []Condition
	DelegateAdmin bool

	score int // calculated policy score
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

type EvaluatorOptions struct {
	AttributeName string
	Label string
	Description string
}

type PolicyCondition struct {
	ItemId int
	Name string
	Evaluator string
	EvaluatorOptions EvaluatorOptions
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
	PolicyConditions []PolicyCondition
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

type AccessResource struct {
	Owner string
	Location string // Elements map[string]interface{}
}

type AccessRequest struct {
	Resource AccessResource
	AccessType string
	User string
	UserGroups []string
	AccessTime time.Time
	ClientIpAddress string
	ForwardedAdresses []string
	RemoteIpAddress string
	ClientType string
	Action string
	RequestData string
	SessionId string
	Context map[string]interface{}
	ClusterName string
}

const (
	// From: https://github.com/apache/ranger/blob//agents-common/src/main/java/org/apache/ranger/plugin/
	// policyevaluator/RangerOptimizedPolicyEvaluator.java
	MATCH_ANY = "*"
	MATCH_ONE = "?"

	ITEM_DEFAULT_SCORE = 1000

	DEFAULT_SCORE = 10000
	DISCOUNT_RESOURCE = 100
	DISCOUNT_USERSGROUPS = 25
	DISCOUNT_ACCESS_TYPES = 25
	DISCOUNT_CUSTOM_CONDITIONS = 25
	DISCOUNT_MATCH_ANY = 25
	DISCOUNT_HAS_MATCH_ANY = 10
	DISCOUNT_HAS_MATCH_ONE = 5
	DISCOUNT_IS_EXCLUDES = 5
	DISCOUNT_IS_RECURSIVE = 5
	CUSTOM_CONDITION_PENALTY = 5
	DYNAMIC_RESOURCE_EVAL_PENALTY = 20

	GROUP_PUBLIC = "public"
	USER_CURRENT = "{USER}"
	USER_OWNER = "{OWNER}"

	WRITE = "write"
	READ = "read"
	WRITE_ACP = "write_acp"
	READ_ACP = "read_acp"

)

// GetPolicy loads the service definition and resource policies from Ranger
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

// checks if an array of strings contains a specific string
func contains(haystack []string, needle string)(bool) {
	for _, hay := range haystack {
		if hay == needle {
			return true
		}
	}
	return false
}

// Calculates the score for a policy item
func (pi *PolicyItem) computeEvalScore(service ServiceDefinition) {
	score := ITEM_DEFAULT_SCORE

	if contains(pi.Groups, GROUP_PUBLIC) {
		score -= DISCOUNT_USERSGROUPS
	} else {
		count := len(pi.Users) + len(pi.Groups)
		score -= int(math.Min(float64(DISCOUNT_USERSGROUPS), float64(count)))
	}

	score -= int(math.Round(float64((DISCOUNT_ACCESS_TYPES * len(pi.Accesses)) / len(service.AccessTypes))))

	customConditionsPenalty := CUSTOM_CONDITION_PENALTY * len(pi.Conditions)
	customConditionsDiscount := DISCOUNT_CUSTOM_CONDITIONS - customConditionsPenalty

	if customConditionsDiscount > 0 {
		score -= customConditionsDiscount
	}

	pi.score = score
}

func hasAccess(names []string, other []string, accesses []Access, accessType string, isOwner bool)(bool) {
	for _, name := range names {
		for i := range other {
			if name == other[i] || other[i] == USER_CURRENT || (other[i] == USER_OWNER && isOwner) {
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

// Check if client ip is in range
func (c *Condition) isInCondition(r *AccessRequest)(error, bool) {
	if c.Type != "ipaddress-in-range" {
		return errors.New("Unknown condition:" + c.Type), false
	}

	for _, cidr := range c.Values {
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Invalid cidr=%s\n", cidr)
			continue
		}
		ip := net.ParseIP(r.ClientIpAddress)
		log.Printf("Checking clientIp=%s cidr=%s\n", r.ClientIpAddress, subnet.String())
		if subnet.Contains(ip) {
			return nil, true
		}
	}

	return nil, false
}

// IsAccessAllowed checks if a user is allowed by policy to access the resource location.
func (s *Service) IsAccessAllowed(r *AccessRequest)(bool) {
	// TODO: Sort on importance of policy
	sort.SliceStable(s.Policies, func(i, j int) bool {return s.Policies[i].Id < s.Policies[j].Id})

	log.Printf("Checking policy for user=%s, groups=%s, access=%s, location=%s\n",
		r.User, r.UserGroups, r.AccessType, r.Resource.Location)

	allowed := false
	resourceMatch := false

	for _, p := range s.Policies {
		// match resource
		for _, v := range p.Resources {
			for _, bucketName := range v.Values {
				if v.IsRecursive {
					bucketName += "*"
				}
				if glob.Glob(bucketName, r.Resource.Location) {
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
			allowed = hasAccess([]string{r.User}, item.Users, item.Accesses, r.AccessType, r.User == r.Resource.Owner)

			// groups
			if !allowed {
				allowed = hasAccess(r.UserGroups, item.Groups, item.Accesses, r.AccessType, false)
			}

			// conditions
			if allowed {
				log.Printf("Checking allow policy conditions\n")
				found := false
				for _, condition := range item.Conditions {
					_, found = condition.isInCondition(r)
					if found {
						break
					}
				}
				if !found && len(item.Conditions) > 0 {
					allowed = false
				}
			}

			// TODO: check exceptions
		}

		log.Printf("Checking deny policy items=%d\n", len(p.DenyPolicyItems))

		for _, item := range p.DenyPolicyItems {
			// allowed signals denial
			allowed = !hasAccess([]string{r.User}, item.Users, item.Accesses, r.AccessType, r.User == r.Resource.Owner)

			// groups
			if allowed {
				allowed = !hasAccess(r.UserGroups, item.Groups, item.Accesses, r.AccessType, false)
			}

			// conditions
			if !allowed {
				log.Printf("Checking deny policy conditions\n")
				found := false
				for _, condition := range item.Conditions {
					_, found = condition.isInCondition(r)
					if found {
						break
					}
				}
				if !found && len(item.Conditions) > 0 {
					allowed = true
				}
			}

			// TODO: check exceptions
		}

		// if we got here we had a resource match
		break
	}

	return allowed
}

