package s3

import (
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"log"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

type Client struct {
	EndPoint string
	AccessKey string
	SecretKey string
}

func (cfg *Client) GetBucketTags(bucket string) (error, []*s3.Tag) {
	creds := credentials.NewStaticCredentials(cfg.AccessKey, cfg.SecretKey, "")

	_, err := creds.Get()
	if err != nil {
		log.Printf("bad credentials: %s\n", err)
		return err, nil
	}

	awsCfg := aws.NewConfig().WithEndpoint(cfg.EndPoint).WithRegion("us-west-1").WithCredentials(creds)

	session, err := session.NewSession(awsCfg)
	client := s3.New(session)

	input := &s3.GetBucketTaggingInput{Bucket: &bucket}

	req, output := client.GetBucketTaggingRequest(input)

	err = req.Send()
	if err != nil {
		log.Printf("Cannot get tags for bucket=%s error=%s\n", bucket, err)
		return err, nil
	}

	return nil, output.TagSet
}
