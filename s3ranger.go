package main

import "time"

type S3Resource struct {
	bucket string
	key string
}

type S3AccessRequest struct {
	Resource S3Resource
	AccessType string
	User string
	UserGroups []string
	AccessTime time.Time
	ClientIP string
	Action string
	ClusterName string
}

