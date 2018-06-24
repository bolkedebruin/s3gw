package main

import (
	"strings"
	"flag"
	"log"
	"time"
	"s3gw/ranger"
	"s3gw/rados"
	"os"
	"github.com/BurntSushi/toml"
	"github.com/patrickmn/go-cache"
	"s3gw/s3"
)

type RangerConfig struct {
	ServiceName string
	EndPoint string
}

type Config struct {
	Address          string
	Port             int
	Endpoint         string
	Ranger           RangerConfig
	Rados            rados.RadosClient
	KeyFile          string
	CertFile         string
	HTTPReadTimeout  int
	HTTPWriteTimeout int
	Auth			 string
	Keytab			 string
}

var service *ranger.Service
var accessKey2Username map[string]string
var radosClient rados.RadosClient
var ownerCache *cache.Cache
var s3Client s3.Client


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


	opts := ServerOptions{
		Port: config.Port,
		Address: config.Address,
		Endpoint: config.Endpoint,
		CertFile: config.CertFile,
		KeyFile: config.KeyFile,
		HTTPWriteTimeout: 60,
		HTTPReadTimeout: 60,

	}

	log.Printf("Listening on: %s\n", config.Port)
	log.Printf("S3 Host Endpoint: %s\n", config.Endpoint)

	ownerCache = cache.New(time.Hour, time.Hour)

	var err error
	service, err = ranger.GetPolicy(config.Ranger.ServiceName, config.Ranger.EndPoint)
	if err != nil {
		log.Fatal("Cannot get initial policy", err)
		panic(err)
	}

	radosClient = config.Rados
	s3Client = s3.Client{
		AccessKey: radosClient.AccessKey,
		SecretKey: radosClient.SecretKey,
		EndPoint: radosClient.EndPoint,
	}

	accessKey2Username, err = radosClient.SyncUserAccessKeys()
	if err != nil {
		log.Fatal("Cannot get initial users from ceph/rados", err)
		panic(err)
	}
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			log.Printf("Updating Ranger Policies and Rados Access accessKey2Username\n")
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
				accessKey2Username = newKeys
			}
		}
	}()

	err = Serve(opts)

	if err != nil {
		log.Fatalf("Cannot start the reverse proxy server: %s\n", err)
	}

}