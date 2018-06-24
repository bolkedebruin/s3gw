package main

import (
	"strconv"
	"net/http"
)

type ServerOptions struct {
	Port int
	Endpoint string
	Address string
	CertFile string
	KeyFile string
	HTTPReadTimeout int
	HTTPWriteTimeout int
}

func Serve(o ServerOptions) error {
	addr := o.Address + ":" + strconv.Itoa(o.Port)

	proxy := NewProxy(o.Endpoint)
	http.HandleFunc("/", proxy.handle)

	if o.CertFile != "" && o.KeyFile != "" {
		return http.ListenAndServeTLS(addr, o.CertFile, o.KeyFile, nil)
	}

	return http.ListenAndServe(addr, nil)
}
