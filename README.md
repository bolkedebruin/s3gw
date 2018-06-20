# S3GW

S3GW is a proxy to RadosGW/S3 (AWS/S3 on the roadmap) that applies Apache Ranger policies to requests to buckets. It 
is accompanied by its sister project RangerS3Plugin.

## Installation

To install `s3gw` you will need `go`. If you have installed `go` run `go get github.com/bolkedebruin/s3gw`. You can
then run `s3gw` if the `GOPATH` is in your `PATH`.

## Configuration

`s3gw` requires a `toml` file for configuration. By default it looks at `/etc/s3gw/s3gw.toml`. The structure is 
as follows:

```
endpoint = "<S3 Endpoint to proxy for:PORT>"            # http://rados.mydomain.com
port = "<PORT TO LISTEN ON>"                            # 80

[ranger]
servicename = "<SERVICE NAME CONFIGURED IN RANGER>"     # S3
endpoint = "<RANGER ENDPOINT:PORT>"                     # http://ranger.mydomain.com:6080

[rados]
endpoint = "<RADOS ADMIN ENDPOINT:PORT>"                # http://rados.mydomain.com         
accesskey = "<ACCESSKEY>"                                 # myaccesskey
secretkey = "<SECRETKEY>"                                 # mysecretkey
adminpath = "/admin"                                    
```
