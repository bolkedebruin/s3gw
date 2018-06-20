package rados

import (
	rgw "github.com/myENA/radosgwadmin"
	rcl "github.com/myENA/restclient"
	"time"
	"context"
	"log"
)

type RadosClient struct {
	EndPoint string
	AccessKey string
	SecretKey string
	AdminPath string
}

func (c *RadosClient) SyncUserAccessKeys() (map[string] string, error) {
	cfg := &rgw.Config{
		ClientConfig: rcl.ClientConfig{
			ClientTimeout: rcl.Duration(time.Second * 10),
		},
		ServerURL: c.EndPoint,
		AdminPath: c.AdminPath,
		AccessKeyID: c.AccessKey,
		SecretAccessKey: c.SecretKey,
	}
	client, err := rgw.NewAdminAPI(cfg)

	if err != nil {
		log.Fatal("Cannot connect to radosgw error=%s\n", err)
		return nil, err
	}

	key2user := make(map[string]string)
	users, err := client.MListUsers(context.Background())

	for _, username := range users {
		user, err := client.MGetUser(context.Background(), username)
		if err != nil {
			continue
		}
		for _, key := range user.Data.Keys {
			key2user[key.AccessKey] = username
		}
	}

	return key2user, nil
}
