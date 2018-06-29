// Copyright 2018 Kodix LLC. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
	"fmt"
	"github.com/gorilla/mux"
	"os"
	"github.com/abramd/log"
	"flag"
	"encoding/json"
	"regexp"
	"net/url"
	"crypto/rsa"
	"io/ioutil"
	"strconv"
	"errors"
	"github.com/gambol99/go-oidc/jose"
	"kodix.ru/utils/health"
	"io"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"kodix.ru/utils/mw"
	"github.com/prometheus/client_golang/prometheus"
	"kodix.ru/utils/must"
	"os/signal"
	"syscall"
	log2 "log"
)

var keys = newKeyCache()
var cfg *config
var regex = make(map[*regexp.Regexp]string)

var argv struct {
	Config string
	Addr   string
	Cap    uint64
}

func init() {
	flag.StringVar(&argv.Config, "c", "config.json", "configuration file path")
	flag.StringVar(&argv.Addr, "addr", ":8081", "server address to listen (e.g. :8080)")
	var v int
	flag.IntVar(&v, "v", 0, "Verbosity level (0-3)")
	flag.Uint64Var(&argv.Cap, "cap", 1000, "max count of simultaneous requests")
	flag.Parse()
	if v >= 0 && v <= 3 {
		log.SetVerbosity(log.Verbosity(v))
	}
	log.SetPrefix("auth-proxy:")
	log.SetFlags(log2.Ldate | log2.Lmicroseconds)
	health.SetCapacity(argv.Cap)
	loadConfig()
	compileRegex()
}

func main() {

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		log.Infoln(" cache cleaner launched..")
		for {
			<-c
			keys.Clear()
			log.Infoln(" keys cache cleared")
		}
	}()

	dur := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "http_request_duration",
		Help: "Duration of http handler",
	}, []string{"code", "method", "endpoint"})
	bp := prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "http_request_backpressure",
		Help: "Back Pressure of service (len/cap)",
	})
	prometheus.MustRegister(dur, bp)

	log.Infoln(" server launched..")
	r := mux.NewRouter()
	r.HandleFunc("/health", health.Health(cacheCount))
	r.Handle("/metrics", promhttp.Handler())
	r.PathPrefix("/").HandlerFunc(mw.MetricsMw(dur, bp, health.BackPressure(http.HandlerFunc(handler))))
	log.Fatalln(http.ListenAndServe(argv.Addr, r))
}

func cacheCount() string {
	return fmt.Sprintf(`"cache":{"len":%d}`, keys.Count())
}

// getKey - get RSA Public Key for given issuer
func getKey(token *jwt.Token) (interface{}, error) {
	var (
		k   *rsa.PublicKey
		err error
	)

	iss, ok := token.Claims.(jwt.MapClaims)["iss"]
	if !ok {
		return nil, errors.New("iss is not specified")
	}

	kid, ok := token.Header["kid"]
	if !ok || kid.(string) == "" {
		return nil, errors.New("kid is not specified")
	}
	tok := fmt.Sprintf("%s%s", iss, kid)

	if !issuerExists(iss.(string)) {
		return nil, errors.New("issuer is not allowed")
	}

	k, ok = keys.Get(tok)
	if !ok {
		k, err = publicKeyFromKeyCloak(iss.(string))
		if err != nil {
			return "", err
		}
		keys.Set(tok, k)
	}
	log.Debugln("getKey: key:", k)
	return k, nil
}

var keycloakSuffix = "/protocol/openid-connect/certs"

type keyCloakResponse struct {
	Keys []jose.JWK `json:"keys"`
}

// publicKeyFromKeyCloak - get RSA Public Key from external storage (KeyCloak)
func publicKeyFromKeyCloak(iss string) (*rsa.PublicKey, error) {
	r, err := http.Get(fmt.Sprintf("%s%s", iss, keycloakSuffix))
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

	log.Debugln(" publicKeyFromKeyCloak: JWK:", j)
	return &rsa.PublicKey{
		N: j.Modulus,
		E: j.Exponent,
	}, nil
}

// handler - http.Handler
func handler(w http.ResponseWriter, r *http.Request) {

	clearXAuthHeaders(r)

	tokStr := r.Header.Get("Authorization")

	// if there is no authorization header, skip token validation
	if tokStr != "" {
		if strings.HasPrefix(tokStr, "bearer ") {
			tokStr = strings.TrimPrefix(tokStr, "bearer ")
		} else if strings.HasPrefix(tokStr, "Bearer ") {
			tokStr = strings.TrimPrefix(tokStr, "Bearer ")
		} else {
			log.Errorln(" http-error:", "token type is not bearer")
			http.Error(w, "token type is not bearer", http.StatusUnauthorized)
			return
		}

		tok, err := jwt.Parse(tokStr, getKey)
		if err != nil {
			log.Errorln(" http-error:", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		setXAuthHeaders(r, tok)
	}

	err := urlRewrite(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cl := http.DefaultClient
	resp, err := cl.Do(r)
	if err != nil {
		log.Errorln(" http-error:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Errorln(" http-error:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// clearXAuthHeaders - remove X-Auth headers from request
func clearXAuthHeaders(r *http.Request) {
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-auth") {
			delete(r.Header, k)
		}
	}
}

// setXAuthHeaders - set X-Auth headers to request from JWT-Token payload
func setXAuthHeaders(r *http.Request, tok *jwt.Token) {
	for k, v := range tok.Claims.(jwt.MapClaims) {
		val := ""
		switch v := v.(type) {
		case float64:
			val = strconv.Itoa(int(v))
		case int:
			val = strconv.Itoa(v)
		case []interface{}:
			for _, h := range v {
				r.Header.Add(fmt.Sprintf("X-Auth-%s", http.CanonicalHeaderKey(k)), h.(string))
			}
			continue
		case map[string]interface{}:
			if k == "resource_access" {
				accessXAuthHeaders(v, r)
				continue
			}
			mapXAuthHeaders(k, v, r)
			continue
		default:
			if _, ok := v.(string); ok {
				val = v.(string)
			}
		}
		r.Header.Set(fmt.Sprintf("X-Auth-%s", http.CanonicalHeaderKey(k)), val)
	}
}

type config struct {
	Rewrite map[string]string `json:"rewrite"`
	Issuers []string          `json:"issuers"`
}

func accessXAuthHeaders(v map[string]interface{}, r *http.Request) {
	for rs, roles := range v {
		if val, ok := roles.(map[string]interface{}); ok {
			for _, role := range val["roles"].([]interface{}) {
				r.Header.Add(fmt.Sprintf("X-Auth-Access-Roles-%s", http.CanonicalHeaderKey(rs)), role.(string))
			}
		}
	}
}

func mapXAuthHeaders(key string, v map[string]interface{}, r *http.Request) {
	for k, h := range v {
		if str, ok := h.(string); ok {
			r.Header.Add(fmt.Sprintf("X-Auth-%s-%s", http.CanonicalHeaderKey(key), http.CanonicalHeaderKey(k)), str)
		}
	}
}

// compileRegex - compile regexps from config
func compileRegex() {
	for k, v := range cfg.Rewrite {
		r := regexp.MustCompile(k)
		regex[r] = v
	}
	log.Infoln(" regexp compiled")
}

func loadConfig() {
	c := new(config)
	must.UnmarshalFile(c, argv.Config)
	cfg = c
	log.Infoln(" configuration loaded")
}

// urlRewrite - rewrite http.Request.URL in given request
func urlRewrite(r *http.Request) error {
	if r.URL == nil {
		return errors.New("empty URL")
	}
	defer log.Debugln(" replaced request:", r)

	u := []byte(fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery))
	for pattern, replace := range regex {
		if pattern.Match(u) {
			u = pattern.ReplaceAll(u, []byte(replace))

			ur, err := url.Parse(string(u))
			if err != nil {
				return err
			}

			r.RequestURI = ""
			r.URL = ur
			return nil
		}
	}
	r.RequestURI = ""
	return nil
}

func issuerExists(iss string) bool {
	for _, v := range cfg.Issuers {
		if v == iss {
			return true
		}
	}
	return false
}
