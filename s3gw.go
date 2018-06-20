package main

import (
	"net/url"
	"net/http/httputil"
	"net/http"
	"fmt"
	"strings"
	"flag"
	"log"
	"time"
	"s3gw/ranger"
	"s3gw/rados"
	"os/user"
	"os"
	"github.com/BurntSushi/toml"
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

func NewProxy(target string) *Proxy {
	url, _ := url.Parse(target)

	return &Proxy{target: url, proxy: httputil.NewSingleHostReverseProxy(url)}
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request){
	header := r.Header.Get("Authorization")
	p.proxy.Transport = &Transport{}

	var username string

	if len(header) > 0 {
		pos1 := strings.Index(header, "Credential") + 11
		pos2 := strings.Index(header, ",") - 1
		credentials := strings.Split(header[pos1:pos2], "/")

		if name, ok := keys[credentials[0]]; !ok {
			log.Printf("Access denied to accessKey=%s due to not found", credentials[0])
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		} else {
			username = name
		}
	} else {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	o, k := GetBucketObjectKey(r.URL.String())
	location := "/" + o
	if len(k) > 0 {
		location += "/" + k
	}

	// load groups of the user from local system
	my_user, err := user.Lookup(username)
	var groups []string

	if err == nil {
		gids, _ := my_user.GroupIds()
		for _, gid := range gids {
			groupname, _ := user.LookupGroupId(gid)
			groups = append(groups, groupname.Name)
		}
	}

	switch strings.ToUpper(r.Method) {
	case "DELETE":
		fmt.Printf("bucket=%s, key=%s, method is HEAD\n", o, k)
		if strings.Index(r.URL.String(), "uploadId=") > 0 {
			fmt.Printf("Skip notification for multipart ABORT")
		}
		if !service.IsAccessAllowed(username, groups, "write", location) {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	case "HEAD":
		fmt.Printf("bucket=%s, key=%s, method is HEAD\n", o, k)
		if !service.IsAccessAllowed(username, groups, "read", location) {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	case "PUT":
		fmt.Printf("bucket=%s, key=%s, method is PUT\n", o, k)
		if !service.IsAccessAllowed(username, groups, "write", location) {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	case "GET":
		fmt.Printf("bucket=%s, key=%s, Method is GET\n", o, k)
		if !service.IsAccessAllowed(username, groups, "read", location) {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	case "POST":
		if strings.Index(r.URL.String(), "?uploads") > 0 {
			fmt.Printf("skip notification for multipart INITIATE")
		}
		if !service.IsAccessAllowed(username, groups, "write", location) {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	default:
		fmt.Printf("Unknown method=%s", r.Method)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	//p.proxy.Transport = &Transport{}
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

	configFile := flag.String("configfile", defaultConfig, "configuration file")

	flag.Parse()

	config := ReadConfig(*configFile)

	log.Printf("Listening on: %s\n", config.Port)
	log.Printf("S3 Host Endpoint: %s\n", config.EndPoint)

	var err error
	service, err = ranger.GetPolicy(config.Ranger.ServiceName, config.Ranger.EndPoint)
	if err != nil {
		log.Fatal("Cannot get initial policy", err)
		panic(err)
	}

	radosClient := config.Rados
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