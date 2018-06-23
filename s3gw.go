package main

import (
	"net/url"
	"net/http/httputil"
	"net/http"
	"strings"
	"flag"
	"log"
	"time"
	"s3gw/ranger"
	"s3gw/rados"
	"os/user"
	"os"
	"github.com/BurntSushi/toml"
	"github.com/patrickmn/go-cache"
)

type Proxy struct {
	target *url.URL
	proxy *httputil.ReverseProxy
}

type Transport struct {

}

type RangerConfig struct {
	ServiceName string
	EndPoint string
}

type Config struct {
	Port string
	EndPoint string
	Ranger RangerConfig
	Rados rados.RadosClient
}

var service *ranger.Service
var keys map[string]string
var radosClient rados.RadosClient
var ownerCache *cache.Cache

func NewProxy(target string) *Proxy {
	u, _ := url.Parse(target)

	return &Proxy{target: u, proxy: httputil.NewSingleHostReverseProxy(u)}
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request){
	header := r.Header.Get("Authorization")
	p.proxy.Transport = &Transport{}

	var username string

	// get remote client ip
	fwdAddress := r.Header.Get("X-Forwarded-For")
	remoteAddress := strings.Split(r.RemoteAddr, ":")[0]
	if fwdAddress != "" {
		// Accessed via proxy
		ips := strings.Split(fwdAddress, ",")
		if len(ips) > 1 {
			fwdAddress = ips[0]
		}
		ips = append(ips, remoteAddress)
		w.Header().Set("X-Forwarded-For", strings.Join(ips, ","))
	} else {
		fwdAddress = remoteAddress
		w.Header().Set("X-Forwarded-For", remoteAddress)
	}

	if len(header) > 0 {
		pos1 := strings.Index(header, "Credential") + 11
		pos2 := strings.Index(header, ",") - 1
		credentials := strings.Split(header[pos1:pos2], "/")

		if name, ok := keys[credentials[0]]; !ok {
			log.Printf("Access denied accessKey=%s due to not found\n", credentials[0])
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		} else {
			username = name
		}
	} else {
		log.Printf("No 'Authorization' header found\n")
		http.Error(w, "No 'Authorization' header found. Access denied", http.StatusForbidden)
		return
	}

	o, k := GetBucketObjectKey(r.URL.String())
	location := "/" + o
	if len(k) > 0 {
		location += "/" + k
	}

	// get owner of the bucket
	owner := ""
	if len(o) > 0 {
		item, found := ownerCache.Get(o)
		if !found {
			log.Printf("Cached owner not found for bucket=%s\n", o)
			item, _ = radosClient.GetBucketOwner(o)
			ownerCache.SetDefault(o, item)
		}
		owner = item.(string)
	}

	// load groups of the user from local system
	my_user, err := user.Lookup(username)
	var groups []string

	if err == nil {
		gids, _ := my_user.GroupIds()
		for _, gid := range gids {
			groupName, _ := user.LookupGroupId(gid)
			groups = append(groups, groupName.Name)
		}
	}

	log.Printf("user=%s, bucket=%s, key=%s, method=%s\n", username, o, k, r.Method)

	query := r.URL.Query()

	req := &ranger.AccessRequest{
		User: username,
		UserGroups: groups,
		Resource: ranger.AccessResource{
			Owner: owner,
			Location: location,
		},
		Action: r.Method,
		AccessTime: time.Now(),
		RemoteIpAddress: r.RemoteAddr,
		ClientIpAddress: fwdAddress,
	}

	switch strings.ToUpper(r.Method) {
	case "DELETE":
		if len(query.Get("uploadId")) > 0 {
			log.Printf("Skip notification for multipart ABORT")
		}
		req.AccessType = ranger.WRITE
		if !service.IsAccessAllowed(req) {
			log.Printf("Access denied location=%s, user=%s, groups=%s, accessType=%s",
				location, username, groups, "write")
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	case "HEAD":
		req.AccessType = ranger.WRITE
		if !service.IsAccessAllowed(req) {
			log.Printf("Access denied location=%s, user=%s, groups=%s, accessType=%s",
				location, username, groups, "read")
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	case "PUT":
		req.AccessType = ranger.WRITE
		if len(query.Get("acl")) > 0 {
			req.AccessType = ranger.WRITE_ACP
		}
		if !service.IsAccessAllowed(req) {
			log.Printf("Access denied location=%s, user=%s, groups=%s, accessType=%s",
				location, username, groups, req.AccessType)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	case "GET":
		req.AccessType = ranger.READ
		if len(query.Get("acl")) > 0 {
			req.AccessType = ranger.READ_ACP
		}
		if !service.IsAccessAllowed(req) {
			log.Printf("Access denied location=%s, user=%s, groups=%s, accessType=%s",
				location, username, groups, req.AccessType)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	case "POST":
		if len(query.Get("uploads")) > 0 {
			log.Printf("skip notification for multipart INITIATE")
		}
		req.AccessType = ranger.WRITE
		if !service.IsAccessAllowed(req) {
			log.Printf("Access denied location=%s, user=%s, groups=%s, accessType=%s",
				location, username, groups, req.AccessType)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	default:
		log.Printf("Access denied location=%s, user=%s, groups=%s, accessType=%s",
			location, username, groups, "unkown")
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	p.proxy.ServeHTTP(w, r)


}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)

	return resp, err
}

func GetBucketObjectKey(s string) (string, string) {
	pos := strings.Index(s, "?")
	if pos > 0 {
		s = s[0:pos-1]
	}
	split := strings.Split(s,"/")

	switch len(split) {
	case 1:
		return "", ""
	case 2:
		return split[1], ""
	default:
		return split[1], split[2]
	}

	return "", ""
}

func ReadConfig(path string)(Config) {
	_, err := os.Stat(path)
	if err != nil {
		log.Fatal("Config file is missing: ", path)
		panic(err)
	}

	var config Config

	_, err = toml.DecodeFile(path, &config)
	if err != nil {
		log.Fatal("Cannot decode toml: ", err)
		panic(err)
	}

	return config
}


func main() {
	const (
		defaultConfig = "/etc/s3gw/sg3w.toml"
	)

	configFile := flag.String("conf", defaultConfig, "configuration file")

	flag.Parse()

	config := ReadConfig(*configFile)

	log.Printf("Listening on: %s\n", config.Port)
	log.Printf("S3 Host Endpoint: %s\n", config.EndPoint)

	ownerCache = cache.New(time.Hour, time.Hour)

	var err error
	service, err = ranger.GetPolicy(config.Ranger.ServiceName, config.Ranger.EndPoint)
	if err != nil {
		log.Fatal("Cannot get initial policy", err)
		panic(err)
	}

	radosClient = config.Rados
	keys, err = radosClient.SyncUserAccessKeys()
	if err != nil {
		log.Fatal("Cannot get initial users from ceph/rados", err)
		panic(err)
	}
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			log.Printf("Updating Ranger Policies and Rados Access keys\n")
			newService, err := ranger.GetPolicy(config.Ranger.ServiceName, config.Ranger.EndPoint)
			if err != nil {
				log.Printf("Cannot refresh Ranger policy due to error %s", err)
			} else {
				service = newService
			}

			newKeys, err := radosClient.SyncUserAccessKeys()
			if err != nil {
				log.Printf("Cannot refresh users from Ceph/Rados due to error %s", err)
			} else {
				keys = newKeys
			}
		}
	}()

	proxy := NewProxy(config.EndPoint)

	http.HandleFunc("/", proxy.handle)
	log.Fatal(http.ListenAndServe(":" + config.Port, nil))


}