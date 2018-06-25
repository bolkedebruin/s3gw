package main

import (
	"net/url"
	"net/http"
	"strings"
	"log"
	"os/user"
	"s3gw/ranger"
	"time"
	"net/http/httputil"
)

type Proxy struct {
	target *url.URL
	proxy *httputil.ReverseProxy
}

type Transport struct {

}

func NewProxy(target string) *Proxy {
	u, _ := url.Parse(target)

	return &Proxy{target: u, proxy: httputil.NewSingleHostReverseProxy(u)}
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request){
	header := r.Header.Get("Authorization")
	p.proxy.Transport = &Transport{}

	var username string
	var fwdAddresses []string
	var clientIp string

	// get remote client ip
	fwdHeader := r.Header.Get("X-Forwarded-For")
	remoteAddress := strings.Split(r.RemoteAddr, ":")[0]
	if fwdHeader != "" {
		// Accessed via proxy
		fwdAddresses = strings.Split(fwdHeader, ",")
		if len(fwdAddresses) > 0 {
			// hope the first one in the list is the client ip
			clientIp = fwdAddresses[1]
		}
		newFwdAddresses := append(fwdAddresses, remoteAddress)
		w.Header().Set("X-Forwarded-For", strings.Join(newFwdAddresses, ","))
	} else {
		w.Header().Set("X-Forwarded-For", remoteAddress)
		clientIp = remoteAddress
	}

	if len(header) > 0 {
		pos1 := strings.Index(header, "Credential") + 11
		pos2 := strings.Index(header, ",") - 1
		credentials := strings.Split(header[pos1:pos2], "/")

		if name, ok := accessKey2Username[credentials[0]]; !ok {
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

	// get tags for this bucket
	err, tags := s3Client.GetBucketTags(location)
	if err != nil {
		log.Printf("Cannot load tags for bucket=%s due to error=%s\n", location, err)
	}
	log.Printf("Tags: %s", tags)

	log.Printf("user=%s, bucket=%s, key=%s, method=%s\n", username, o, k, r.Method)

	query := r.URL.Query()

	req := &ranger.AccessRequest{
		User: username,
		UserGroups: groups,
		Resource: ranger.AccessResource{
			Owner: owner,
			Location: location,
		},
		Action:          	r.Method,
		AccessTime:      	time.Now(),
		RemoteIpAddress: 	remoteAddress,
		ClientIpAddress: 	clientIp,
		ForwardedAdresses:	fwdAddresses,
	}

	switch strings.ToUpper(r.Method) {
	case "DELETE":
		if len(query.Get("uploadId")) > 0 {
			log.Printf("Skip notification for multipart ABORT")
		}
		req.AccessType = ranger.Write
		if !service.IsAccessAllowed(req) {
			log.Printf("Access denied location=%s, user=%s, groups=%s, accessType=%s",
				location, username, groups, "write")
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	case "HEAD":
		req.AccessType = ranger.Read
		if !service.IsAccessAllowed(req) {
			log.Printf("Access denied location=%s, user=%s, groups=%s, accessType=%s",
				location, username, groups, "read")
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	case "PUT":
		req.AccessType = ranger.Write
		if len(query.Get("acl")) > 0 {
			req.AccessType = ranger.WriteAcp
		}
		if !service.IsAccessAllowed(req) {
			log.Printf("Access denied location=%s, user=%s, groups=%s, accessType=%s",
				location, username, groups, req.AccessType)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		break
	case "GET":
		req.AccessType = ranger.Read
		if len(query.Get("acl")) > 0 {
			req.AccessType = ranger.ReadAcp
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
		req.AccessType = ranger.Write
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
