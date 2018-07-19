// Copyright 2018 Kodix LLC. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/kodix/log"
	"github.com/kodix/utils/health"
	"github.com/kodix/utils/must"
	"github.com/kodix/utils/mw"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io"
	log2 "log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
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
	loadAllJwksAddresses()
}

func main() {

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		log.Infoln("cache cleaner launched..")
		for {
			<-c
			keys.Clear()
			log.Infoln("keys cache cleared")
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

	log.Infoln("server launched..")
	r := mux.NewRouter()
	r.HandleFunc("/health", health.Health(cacheCount))
	r.Handle("/metrics", promhttp.Handler())
	r.PathPrefix("/").HandlerFunc(mw.MetricsMw(dur, bp, requestIdMw(health.BackPressure(http.HandlerFunc(handler)))))
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
	return k, nil
}

// handler - http.Handler
func handler(w http.ResponseWriter, r *http.Request) {
	logger := mw.LoggerFromRequest(r)

	clearXAuthHeaders(r)

	tokStr := r.Header.Get("Authorization")

	// if there is no authorization header, skip token validation
	if tokStr != "" {
		if strings.HasPrefix(tokStr, "bearer ") {
			tokStr = strings.TrimPrefix(tokStr, "bearer ")
		} else if strings.HasPrefix(tokStr, "Bearer ") {
			tokStr = strings.TrimPrefix(tokStr, "Bearer ")
		} else {
			logger.Errorln("http-error:", "token type is not bearer")
			http.Error(w, "token type is not bearer", http.StatusUnauthorized)
			return
		}

		tok, err := jwt.Parse(tokStr, getKey)
		if err != nil {
			logger.Errorln("jwt parsing error:", err)
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
		logger.Errorln("next service: http-error:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		logger.Errorln("response body copying error:", err)
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
		case map[string]interface{}: // TODO: replace with recursive func
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
	Issuers map[string]string `json:"issuers"`
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
	log.Infoln("regexp compiled")
}

func loadConfig() {
	c := new(struct {
		Rewrite map[string]string `json:"rewrite"`
		Issuers []string `json:"issuers"`
	})
	cfg = new(config)
	must.UnmarshalFile(c, argv.Config)
	cfg.Rewrite = c.Rewrite
	cfg.Issuers = make(map[string]string)
	for _, v := range c.Issuers {
		cfg.Issuers[v] = ""
	}
	log.Infoln("configuration loaded")
}

// urlRewrite - rewrite http.Request.URL in given request
func urlRewrite(r *http.Request) error {
	logger := mw.LoggerFromRequest(r)
	if r.URL == nil {
		return errors.New("empty URL")
	}
	defer logger.Infoln("replaced request:", r)

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

var requestIdKey = "X-Request-Id"

func requestIdMw(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIdKey)
		if id == "" {
			id = randomRequestId().String()
			r.Header.Set(requestIdKey, id)
		}
		next.ServeHTTP(w, r)
	}
}

func randomRequestId() UUID {
	return New()
}

func issuerExists(iss string) bool {
	for k := range cfg.Issuers {
		if k == iss {
			return true
		}
	}
	return false
}

// UUID is a 128 bit (16 byte) Universal Unique IDentifier as defined in RFC
// 4122.
type UUID [16]byte

// New creates a new random (Version 4) UUID or panics. The strength of the
// UUIDs is based on the strength of the crypto/rand package.
func New() UUID {
	uuid, err := NewUUID()
	if err != nil {
		panic(err)
	}
	return uuid
}

// NewUUID returns a random (Version 4) UUID.
func NewUUID() (UUID, error) {
	var uuid UUID
	_, err := io.ReadFull(rand.Reader, uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return uuid, err
}

// encode converts uuid to string form (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
func encode(uuid UUID, data []byte) {
	hex.Encode(data[:], uuid[:4])
	data[8] = '-'
	hex.Encode(data[9:13], uuid[4:6])
	data[13] = '-'
	hex.Encode(data[14:18], uuid[6:8])
	data[18] = '-'
	hex.Encode(data[19:23], uuid[8:10])
	data[23] = '-'
	hex.Encode(data[24:], uuid[10:])
}

// String returns the string form of uuid, xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
func (uuid UUID) String() string {
	var data [36]byte
	encode(uuid, data[:])
	return string(data[:])
}
