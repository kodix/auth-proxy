// Copyright 2018 Kodix LLC. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/gambol99/go-oidc/jose"
	"io/ioutil"
	"net/http"
	"strings"
)

var openIDConfigPath = ".well-known/openid-configuration"

type openIDConfig struct {
	JwksURI string `json:"jwks_uri"`
}

type keyCloakResponse struct {
	Keys []jose.JWK `json:"keys"`
}

func loadJwksAddress(iss string) (string, error) {
	var resp = new(openIDConfig)
	r, err := http.Get(fmt.Sprintf("%s/%s", strings.TrimSuffix(iss, "/"), openIDConfigPath))
	if err != nil {
		return "", err
	}
	err = json.NewDecoder(r.Body).Decode(resp)
	if err != nil {
		return "", err
	}
	return resp.JwksURI, nil
}

// publicKeyFromKeyCloak - get RSA Public Key from external storage (KeyCloak)
func publicKeyFromKeyCloak(iss string) (*rsa.PublicKey, error) { // TODO: refactor
	var (
		certPath string
		err      error
	)
	certPath, _ = cfg.CertPath(iss)
	if certPath == "" {
		certPath, err = loadJwksAddress(iss)
		if err != nil {
			return nil, err
		}
	}
	r, err := http.Get(certPath)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	k := keyCloakResponse{}
	err = json.Unmarshal(b, &k)
	if err != nil {
		return nil, err
	}

	j := k.Keys[0]

	return &rsa.PublicKey{
		N: j.Modulus,
		E: j.Exponent,
	}, nil
}
