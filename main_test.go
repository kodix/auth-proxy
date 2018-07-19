// Copyright 2018 Kodix LLC. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/kodix/log"
)

func Test_clearXAuthHeaders(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name string
		args args
		want *http.Request
	}{
		{
			"not valid x-auth header",
			args{&http.Request{Header: http.Header{"-X-Auth-Test": []string{"test"}}}},
			&http.Request{Header: http.Header{"-X-Auth-Test": []string{"test"}}},
		},
		{
			"valid x-auth header",
			args{&http.Request{Header: http.Header{"X-Auth-Test": []string{"test", "test"}}}},
			&http.Request{Header: http.Header{}},
		},
		{
			"valid x-auth header (lowercase)",
			args{&http.Request{Header: http.Header{"x-auth-Test": []string{"test", "test"}}}},
			&http.Request{Header: http.Header{}},
		},
		{
			"valid x-auth header (uppercase)",
			args{&http.Request{Header: http.Header{"X-AUTH-Test": []string{"test", "test"}}}},
			&http.Request{Header: http.Header{}},
		},
		{
			"valid x-auth headers",
			args{&http.Request{Header: http.Header{"X-Auth-Test": []string{"test"}, "X-Auth-User": []string{"test"}}}},
			&http.Request{Header: http.Header{}},
		},
		{
			"valid & invalid x-auth headers",
			args{&http.Request{Header: http.Header{"X-Auth-Test": []string{"test"}, "X-Auth-User": []string{"test"}, "Auth": []string{"base"}}}},
			&http.Request{Header: http.Header{"Auth": []string{"base"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearXAuthHeaders(tt.args.r)
			if !reflect.DeepEqual(tt.args.r, tt.want) {
				t.Errorf("Error: %s. Want: %+v, got: %+v", tt.name, tt.want, tt.args.r)
			}
		})
	}
}

func Test_setXAuthHeaders(t *testing.T) {

	pkey := decPKey()
	keys.Set("test", pkey)
	type args struct {
		r   *http.Request
		tok *jwt.Token
	}
	tests := []struct {
		name string
		args args
		want *http.Request
	}{
		{
			"method saved",
			args{
				&http.Request{Header: http.Header{}, Method: http.MethodPost},
				&jwt.Token{Claims: jwt.MapClaims{"iss": "test"}},
			},
			&http.Request{Header: http.Header{"X-Auth-Iss": []string{"test"}}, Method: http.MethodPost},
		},
		{
			"2 claims",
			args{
				&http.Request{Header: http.Header{}},
				&jwt.Token{Claims: jwt.MapClaims{"iss": "test", "sub": "qwerty"}},
			},
			&http.Request{Header: http.Header{"X-Auth-Iss": []string{"test"}, "X-Auth-Sub": []string{"qwerty"}}},
		},
		{
			"another headers saved",
			args{
				&http.Request{Header: http.Header{"Content-Type": []string{"application/json"}}},
				&jwt.Token{Claims: jwt.MapClaims{"iss": "test", "sub": "qwerty"}},
			},
			&http.Request{Header: http.Header{"Content-Type": []string{"application/json"}, "X-Auth-Iss": []string{"test"}, "X-Auth-Sub": []string{"qwerty"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setXAuthHeaders(tt.args.r, tt.args.tok)
			if !reflect.DeepEqual(tt.args.r, tt.want) {
				t.Errorf("Error: %s. Want: %+v, got: %+v", tt.name, tt.want, tt.args.r)
			}
		})
	}
}

type TestWriter struct {
	h http.Header
}

func NewWriter() *TestWriter {
	return &TestWriter{
		h: make(http.Header),
	}
}

func (w *TestWriter) Header() http.Header {
	return w.h
}

func (TestWriter) Write(b []byte) (int, error) {
	log.Infoln(b)
	return 0, nil
}

func (w *TestWriter) WriteHeader(v int) {
	w.h.Set("Status", fmt.Sprintf("%d", v))
}

/*func Test_handler(t *testing.T) {
        // FIXME: replace public key with jwk format (da@kodix.ru)
        pkey := decPKey()
        keys.Set("http://localhost:8080/auth/realms/master", pkey)
        type args struct {
                w http.ResponseWriter
                r *http.Request
        }
        tests := []struct {
                name string
                args args
                want *http.Request
        }{
                {
                        "",
                        args{
                                r: &http.Request{
                                        URL:    &url.URL{Path: "/test", RawQuery: "test=test"},
                                        Header: http.Header{"Authorization": []string{"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InV1aWQifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiaWF0IjoxNTE2MjM5MDIyfQ.PqDqS9clU9q7_Z_Wc4x1nhtF_-39fnP9EKnM80o4wl01RullPVZ7SQ8sHqI2AooZGZ-f3HfDuKlgM5kOPkKclPIKuJoGmfmWYRi0uA8NWRiPZ0bkNfLT_gIOGRqKhiYc85XFkfDn5XY7gxgTUxwLcrEaubLz1XuGK2gHzHE4Tk9Nx7uYrZ_F-dJOKbch-OdLaHB0BAzmPU5TiDpUAfznJEDlXwowHXuaG2ZFwMKlLlPpUBCO2nXoAMUqofiuYlFi4YzYDhIXeM6J7jULOarYHl2sI9p9ZM-bd5bbwMNBwIPXOTMYPMYbMS-A9wys1Lcd5-agilBj2v4CV1UoPhlsRw"}}},
                                w: NewWriter(),
                        },
                        &http.Request{
                                URL:    &url.URL{Path: "/test", RawQuery: "test=test"},
                                Header: http.Header{"X-Auth-Iss": []string{"http://localhost:8080/auth/realms/master"}, "X-Auth-Iat": []string{"1516239022"}, "Authorization": []string{"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InV1aWQifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiaWF0IjoxNTE2MjM5MDIyfQ.PqDqS9clU9q7_Z_Wc4x1nhtF_-39fnP9EKnM80o4wl01RullPVZ7SQ8sHqI2AooZGZ-f3HfDuKlgM5kOPkKclPIKuJoGmfmWYRi0uA8NWRiPZ0bkNfLT_gIOGRqKhiYc85XFkfDn5XY7gxgTUxwLcrEaubLz1XuGK2gHzHE4Tk9Nx7uYrZ_F-dJOKbch-OdLaHB0BAzmPU5TiDpUAfznJEDlXwowHXuaG2ZFwMKlLlPpUBCO2nXoAMUqofiuYlFi4YzYDhIXeM6J7jULOarYHl2sI9p9ZM-bd5bbwMNBwIPXOTMYPMYbMS-A9wys1Lcd5-agilBj2v4CV1UoPhlsRw"}}},
                },
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        handler(tt.args.w, tt.args.r)
                        if !reflect.DeepEqual(tt.args.r, tt.want) {
                                t.Errorf("Error: %s. Want: %+v, got: %+v", tt.name, tt.want.Header, tt.args.r.Header)
                        }
                })
        }
        keys.Clear()
}*/

func decPKey() *rsa.PublicKey {
	f, err := os.Open("tst_rsa")
	if err != nil {
		panic(err)
	}
	pubPEM, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}
	return &pub.PublicKey
}

func TestTest(t *testing.T) {
	j := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjkyMmNmOGJlLTk2ZmYtNGFjYS1hNjVjLTEwYjQ1OGExNWU3OCJ9.eyJqdGkiOiI0NjgwOGMyMy1hNTdkLTRjNGMtOTM1OC1kMTc4NmI2ZDYyZDUiLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MCwiaWF0IjoxNTI4MjEyODQ4LCJpc3MiOiJodHRwczovL3Z3LmtvZGl4LnJ1L2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6InZ3LW9mZmVycyIsInN1YiI6ImJjZTNiMTViLTUxMjYtNDJkZS1iZWE4LTEyYjRjMjA4ZmY1OSIsInR5cCI6IkJlYXJlciIsImF6cCI6InZ3LW9mZmVycyIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6ImMxOWY5ZjM0LTk2YTUtNGY5Yy1hYTNjLWVjZDExOGY5NTc1NiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtYXN0ZXItcmVhbG0iOnsicm9sZXMiOlsibWFuYWdlLXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJjbGllbnRIb3N0IjoiNDYuMTQ4LjE5Ni43NiIsImNsaWVudElkIjoidnctb2ZmZXJzIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LXZ3LW9mZmVycyIsImNsaWVudEFkZHJlc3MiOiI0Ni4xNDguMTk2Ljc2IiwiZW1haWwiOiJzZXJ2aWNlLWFjY291bnQtdnctb2ZmZXJzQHBsYWNlaG9sZGVyLm9yZyJ9.flJSzqDF7HSJuC86QPLjIaTYMoAQC8Y0y0PaTmA8o2yTh_sSmALuBOgBh5Qrw_euyWbqjtj93kO7O6k3gmM9NYG7wzLh_X99pjC_-MwYVvglW5AR7aG1_F46iQi0qWJc6j1EYM5p43BZkzmopU6HFe0LFZ0RyScV31DTLLuCUeT1vjYyiAFxzzT5zN2F7yJVGQ3f0HI6qJsxLXc6138JSWIphyoGlXYf3MTFWLlOvVT_E0-UalDadfLwch1GRcRzdE8p79bhElFgzXH45T6F5qtKJkLgCZjvv5fGk7aVcpB1fxrFgVyyu_Hu2fFYazwkrEmr-7_0-QBwPsmLMJRcbg"
	pk, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwTkhm8M9OpEF8SuQaq0zcBlkB6Bhxvw1k3WIuAL18BuGvLmF
yjR9faauupAb9SmpONRCIwmxj0s371AzzBQuPBdfAk/0xu7rMybdEV1ZEqfhw/9w
7fJNfzSPUo/0OICGZORSPSStUJUvGOzWGucVOlEjd2eHkqct7ntV+nbkjBrF3kta
Kt1SGAv6eeSDBPcBR0rAz6DTqN6J83Cgyf8oXsVTEbArxg5489v/PyakXDW9GqG3
ta2mbzpvrqI+bSOxWDyJcjw2sP7NQJqoiycjrnynr028pUKuQEMyNCsnVz84F8N6
2Wc9+QlGj7Mr0qNQ0HsUJsUiBAGxh+ZVcdo6FwIDAQABAoIBAGX2FuUSDsJT+tW7
zlZslUMnMuDPYilVt5PbpsyrS0przBrUr2P3dO0UQwnRt98UH+cMIuZIXDkoURjo
spyTXZ56GrmmpZ1AQD7a2Dcski9FBd6eceIuRXTFsIe5zP7v23tr/HWlYAuw3YyC
lazWmh4O6O8+Y40gyR0aWlFz4cCICLEhusR48n31uKaEXlcdHZ6N+vmgvLoIn3X1
l49qXZfPIykOaecRFwSDvKwLmX72kMp7bNV1PQBll27K+oUBXoVM3xnLTo0YsPqc
vji2RTz6rQwcAQt0ih6kQTMdtizo2bcmOiOGAb768BetXP7G/LOjEpexdyzYm4aR
1e7xqCECgYEA8Yt+IEyFNdGb45qGnmpcRTKEN5BI0BxTPlB9dB/M8BpsC4wP/qnB
lzhJfLIq9W8icu5vJycG4TDzJSpqqlal6icGiOb+UsINzTSuCqy8tV1OgI62DmEY
doSXjLXiRUJWpwvsGSWEkNr9foWWyFufwZ4IgQsB7GY4D0ZN4ftWRWcCgYEAzMlX
hRsZNFV6ZX/6by6krZ6AbF2oulcUsHJUe8/lxjkbO2Uw8H7Xmof6lH71+NQKKg9x
1rgEFxSVVEy5nZP08HiNm4ZUtawaRLl8Ix/50yMV7oWqZJ98KK64hUKZYglO/1un
wmVOmjgLvm0wkfORdDfBvhL9e5URsbf89Uv0R9ECgYB6xKmghQQX7KfNMVdG4Uxw
p1JoY19+10bAH20EPr2NNADChbgDegi5cZR4Wp5XDNt3ixTX05A9mQGcXEjGty+x
KZC6uJ1/Nr6JFEN5jX6EuB4UXXTPLi6e3pmgnTmadjNQyFCCH32XmpbJXeDbiSZT
5Jzx6cRagUHxEYy4VWTt9QKBgDl5NHfl4BABAWXlIgr8Izma514Cdy087VCL9cv9
z/Xu5wanYrHMV4RGL3xnmW7pS6T8Sq3BXVyA6VwMYHeqI68tlkiUzcdi8shg6kcN
XVb1XN1hZC3zWKwuRRkZVOTfyez+8zkqp4G+wwUBrgT4P9VHJLfMqpl5f8rJ4VOS
qo9RAoGAHrOFC0uJfQfa68O/nMUIp7eyycT/IJUwm7iQXcSr8HaGWrQAFdrBTG77
dkSoSbjT6FbfVFsaQY/2XMKh206wmHfMeLAVu55IyRvtdQMgonwd4O7mMYaI6Icg
nU4OxKmmF4BrYNpl5cS119PAApmnaRe3oebSgNNxFOsDUQKMtGg=
-----END RSA PRIVATE KEY-----`))
	if err != nil {
		panic(err)
	}
	tok, err := jwt.Parse(j, func(*jwt.Token) (interface{}, error) {
		return &pk.PublicKey, nil
	})
	if err != nil {
		panic(err)
	}
	log.Errorln(tok.Claims)
	r, _ := http.NewRequest(http.MethodGet, "", nil)
	setXAuthHeaders(r, tok)
	log.Errorln(r.Header)
}

func Test_urlRewrite(t *testing.T) {
	r1, _ := http.NewRequest(http.MethodGet, "test?test=test", nil)
	r2, _ := http.NewRequest(http.MethodGet, "test?test=test", nil)
	r2.URL = nil
	r3, _ := http.NewRequest(http.MethodGet, "/test/dictionary?test=test", nil)
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"success",
			args{
				r1,
			},
			false,
		},
		{
			"error",
			args{
				r2,
			},
			true,
		},
		{
			"success & matched",
			args{
				r3,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := urlRewrite(tt.args.r); (err != nil) != tt.wantErr {
				t.Errorf("urlRewrite() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TODO: replace
func Test_handler(t *testing.T) {
	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "http://localhost/test/test", nil)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	handler(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("")
	}

	j := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjkyMmNmOGJlLTk2ZmYtNGFjYS1hNjVjLTEwYjQ1OGExNWU3OCJ9.eyJqdGkiOiI0NjgwOGMyMy1hNTdkLTRjNGMtOTM1OC1kMTc4NmI2ZDYyZDUiLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MCwiaWF0IjoxNTI4MjEyODQ4LCJpc3MiOiJodHRwczovL3Z3LmtvZGl4LnJ1L2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6InZ3LW9mZmVycyIsInN1YiI6ImJjZTNiMTViLTUxMjYtNDJkZS1iZWE4LTEyYjRjMjA4ZmY1OSIsInR5cCI6IkJlYXJlciIsImF6cCI6InZ3LW9mZmVycyIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6ImMxOWY5ZjM0LTk2YTUtNGY5Yy1hYTNjLWVjZDExOGY5NTc1NiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtYXN0ZXItcmVhbG0iOnsicm9sZXMiOlsibWFuYWdlLXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJjbGllbnRIb3N0IjoiNDYuMTQ4LjE5Ni43NiIsImNsaWVudElkIjoidnctb2ZmZXJzIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LXZ3LW9mZmVycyIsImNsaWVudEFkZHJlc3MiOiI0Ni4xNDguMTk2Ljc2IiwiZW1haWwiOiJzZXJ2aWNlLWFjY291bnQtdnctb2ZmZXJzQHBsYWNlaG9sZGVyLm9yZyJ9.flJSzqDF7HSJuC86QPLjIaTYMoAQC8Y0y0PaTmA8o2yTh_sSmALuBOgBh5Qrw_euyWbqjtj93kO7O6k3gmM9NYG7wzLh_X99pjC_-MwYVvglW5AR7aG1_F46iQi0qWJc6j1EYM5p43BZkzmopU6HFe0LFZ0RyScV31DTLLuCUeT1vjYyiAFxzzT5zN2F7yJVGQ3f0HI6qJsxLXc6138JSWIphyoGlXYf3MTFWLlOvVT_E0-UalDadfLwch1GRcRzdE8p79bhElFgzXH45T6F5qtKJkLgCZjvv5fGk7aVcpB1fxrFgVyyu_Hu2fFYazwkrEmr-7_0-QBwPsmLMJRcbg"
	w = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, "http://localhost/test/test", nil)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	r.Header.Set("Authorization", j)
	handler(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("")
	}

	j = "bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjkyMmNmOGJlLTk2ZmYtNGFjYS1hNjVjLTEwYjQ1OGExNWU3OCJ9.eyJqdGkiOiI0NjgwOGMyMy1hNTdkLTRjNGMtOTM1OC1kMTc4NmI2ZDYyZDUiLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MCwiaWF0IjoxNTI4MjEyODQ4LCJpc3MiOiJodHRwczovL3Z3LmtvZGl4LnJ1L2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6InZ3LW9mZmVycyIsInN1YiI6ImJjZTNiMTViLTUxMjYtNDJkZS1iZWE4LTEyYjRjMjA4ZmY1OSIsInR5cCI6IkJlYXJlciIsImF6cCI6InZ3LW9mZmVycyIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6ImMxOWY5ZjM0LTk2YTUtNGY5Yy1hYTNjLWVjZDExOGY5NTc1NiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtYXN0ZXItcmVhbG0iOnsicm9sZXMiOlsibWFuYWdlLXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJjbGllbnRIb3N0IjoiNDYuMTQ4LjE5Ni43NiIsImNsaWVudElkIjoidnctb2ZmZXJzIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LXZ3LW9mZmVycyIsImNsaWVudEFkZHJlc3MiOiI0Ni4xNDguMTk2Ljc2IiwiZW1haWwiOiJzZXJ2aWNlLWFjY291bnQtdnctb2ZmZXJzQHBsYWNlaG9sZGVyLm9yZyJ9.flJSzqDF7HSJuC86QPLjIaTYMoAQC8Y0y0PaTmA8o2yTh_sSmALuBOgBh5Qrw_euyWbqjtj93kO7O6k3gmM9NYG7wzLh_X99pjC_-MwYVvglW5AR7aG1_F46iQi0qWJc6j1EYM5p43BZkzmopU6HFe0LFZ0RyScV31DTLLuCUeT1vjYyiAFxzzT5zN2F7yJVGQ3f0HI6qJsxLXc6138JSWIphyoGlXYf3MTFWLlOvVT_E0-UalDadfLwch1GRcRzdE8p79bhElFgzXH45T6F5qtKJkLgCZjvv5fGk7aVcpB1fxrFgVyyu_Hu2fFYazwkrEmr-7_0-QBwPsmLMJRcbg"
	w = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, "http://localhost/test/test", nil)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	r.Header.Set("Authorization", j)
	handler(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("")
	}

	j = "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjkyMmNmOGJlLTk2ZmYtNGFjYS1hNjVjLTEwYjQ1OGExNWU3OCJ9.eyJqdGkiOiI0NjgwOGMyMy1hNTdkLTRjNGMtOTM1OC1kMTc4NmI2ZDYyZDUiLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MCwiaWF0IjoxNTI4MjEyODQ4LCJpc3MiOiJodHRwczovL3Z3LmtvZGl4LnJ1L2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6InZ3LW9mZmVycyIsInN1YiI6ImJjZTNiMTViLTUxMjYtNDJkZS1iZWE4LTEyYjRjMjA4ZmY1OSIsInR5cCI6IkJlYXJlciIsImF6cCI6InZ3LW9mZmVycyIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6ImMxOWY5ZjM0LTk2YTUtNGY5Yy1hYTNjLWVjZDExOGY5NTc1NiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtYXN0ZXItcmVhbG0iOnsicm9sZXMiOlsibWFuYWdlLXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJjbGllbnRIb3N0IjoiNDYuMTQ4LjE5Ni43NiIsImNsaWVudElkIjoidnctb2ZmZXJzIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LXZ3LW9mZmVycyIsImNsaWVudEFkZHJlc3MiOiI0Ni4xNDguMTk2Ljc2IiwiZW1haWwiOiJzZXJ2aWNlLWFjY291bnQtdnctb2ZmZXJzQHBsYWNlaG9sZGVyLm9yZyJ9.flJSzqDF7HSJuC86QPLjIaTYMoAQC8Y0y0PaTmA8o2yTh_sSmALuBOgBh5Qrw_euyWbqjtj93kO7O6k3gmM9NYG7wzLh_X99pjC_-MwYVvglW5AR7aG1_F46iQi0qWJc6j1EYM5p43BZkzmopU6HFe0LFZ0RyScV31DTLLuCUeT1vjYyiAFxzzT5zN2F7yJVGQ3f0HI6qJsxLXc6138JSWIphyoGlXYf3MTFWLlOvVT_E0-UalDadfLwch1GRcRzdE8p79bhElFgzXH45T6F5qtKJkLgCZjvv5fGk7aVcpB1fxrFgVyyu_Hu2fFYazwkrEmr-7_0-QBwPsmLMJRcbg"
	w = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, "http://localhost/test/test", nil)
	if err != nil {
		t.Errorf("%s", err.Error())
	}
	r.Header.Set("Authorization", j)
	handler(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("")
	}

	/*pk, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(`-----BEGIN RSA PRIVATE KEY-----
	MIIEogIBAAKCAQEAwTkhm8M9OpEF8SuQaq0zcBlkB6Bhxvw1k3WIuAL18BuGvLmF
	yjR9faauupAb9SmpONRCIwmxj0s371AzzBQuPBdfAk/0xu7rMybdEV1ZEqfhw/9w
	7fJNfzSPUo/0OICGZORSPSStUJUvGOzWGucVOlEjd2eHkqct7ntV+nbkjBrF3kta
	Kt1SGAv6eeSDBPcBR0rAz6DTqN6J83Cgyf8oXsVTEbArxg5489v/PyakXDW9GqG3
	ta2mbzpvrqI+bSOxWDyJcjw2sP7NQJqoiycjrnynr028pUKuQEMyNCsnVz84F8N6
	2Wc9+QlGj7Mr0qNQ0HsUJsUiBAGxh+ZVcdo6FwIDAQABAoIBAGX2FuUSDsJT+tW7
	zlZslUMnMuDPYilVt5PbpsyrS0przBrUr2P3dO0UQwnRt98UH+cMIuZIXDkoURjo
	spyTXZ56GrmmpZ1AQD7a2Dcski9FBd6eceIuRXTFsIe5zP7v23tr/HWlYAuw3YyC
	lazWmh4O6O8+Y40gyR0aWlFz4cCICLEhusR48n31uKaEXlcdHZ6N+vmgvLoIn3X1
	l49qXZfPIykOaecRFwSDvKwLmX72kMp7bNV1PQBll27K+oUBXoVM3xnLTo0YsPqc
	vji2RTz6rQwcAQt0ih6kQTMdtizo2bcmOiOGAb768BetXP7G/LOjEpexdyzYm4aR
	1e7xqCECgYEA8Yt+IEyFNdGb45qGnmpcRTKEN5BI0BxTPlB9dB/M8BpsC4wP/qnB
	lzhJfLIq9W8icu5vJycG4TDzJSpqqlal6icGiOb+UsINzTSuCqy8tV1OgI62DmEY
	doSXjLXiRUJWpwvsGSWEkNr9foWWyFufwZ4IgQsB7GY4D0ZN4ftWRWcCgYEAzMlX
	hRsZNFV6ZX/6by6krZ6AbF2oulcUsHJUe8/lxjkbO2Uw8H7Xmof6lH71+NQKKg9x
	1rgEFxSVVEy5nZP08HiNm4ZUtawaRLl8Ix/50yMV7oWqZJ98KK64hUKZYglO/1un
	wmVOmjgLvm0wkfORdDfBvhL9e5URsbf89Uv0R9ECgYB6xKmghQQX7KfNMVdG4Uxw
	p1JoY19+10bAH20EPr2NNADChbgDegi5cZR4Wp5XDNt3ixTX05A9mQGcXEjGty+x
	KZC6uJ1/Nr6JFEN5jX6EuB4UXXTPLi6e3pmgnTmadjNQyFCCH32XmpbJXeDbiSZT
	5Jzx6cRagUHxEYy4VWTt9QKBgDl5NHfl4BABAWXlIgr8Izma514Cdy087VCL9cv9
	z/Xu5wanYrHMV4RGL3xnmW7pS6T8Sq3BXVyA6VwMYHeqI68tlkiUzcdi8shg6kcN
	XVb1XN1hZC3zWKwuRRkZVOTfyez+8zkqp4G+wwUBrgT4P9VHJLfMqpl5f8rJ4VOS
	qo9RAoGAHrOFC0uJfQfa68O/nMUIp7eyycT/IJUwm7iQXcSr8HaGWrQAFdrBTG77
	dkSoSbjT6FbfVFsaQY/2XMKh206wmHfMeLAVu55IyRvtdQMgonwd4O7mMYaI6Icg
	nU4OxKmmF4BrYNpl5cS119PAApmnaRe3oebSgNNxFOsDUQKMtGg=
	-----END RSA PRIVATE KEY-----`))
			keys.Set("http://localhost/test/test", pk.Public().(*rsa.PublicKey))

			j = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoyMDAwMDAwMDAwMCwiaWF0IjoxNTE2MjM5MDIyfQ.ssOsv13F2gawY2i9ai3Za3CBck_ieRxzsryCk2WB-n-2ZsF9kjgTCTPqHkhcwHvc-Kh60f07pkdafgyAykvQQjySEBHx0b-qfsg3MNZjJewOPCrAHe-0p4PU0c_JLoWzbd-npe7k6U3Pov4muw_JCquGgouJ892q3alrmPeE3vpkVQcfur7WkBd4qPFr3AUVtTsECDVcPrlmMG_NxhhjwcGK8yvozTw4XtyjI0fwe06ECCtYOK4C5jHKPJhIr3Tp5sqe5-NR_lYWeBhNV25POsxonwBDVwt1RaslHPIplLSMmj8xdfllmlrbTPshCuBAl1Ocd05KoYEjEo3ZHbXXUg"
			w = httptest.NewRecorder()
			r, err = http.NewRequest(http.MethodGet, "http://localhost/test/test", nil)
			if err != nil {
					t.Errorf("%s", err.Error())
			}
			r.Header.Set("Authorization", j)
			handler(w, r)
			if w.Code == http.StatusUnauthorized {
					t.Errorf()
			}*/
}

func Test_publicKeyFromKeyCloak(t *testing.T) {
	st := http.NewServeMux()
	st.HandleFunc("/auth/realms/test"+openIDConfigPath, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"keys":[{
                "alg":"RS256",
                        "e":"AQAB",
                        "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
                        }]}`))
	})
	st.HandleFunc("/auth/realms/error"+openIDConfigPath, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	go func() {
		log.Fatalln(http.ListenAndServe(":1112", st))
	}()

	// success
	_, err := publicKeyFromKeyCloak("http://localhost:1112/auth/realms/test")
	if err != nil {
		t.Error(err)
	}

	// http error
	_, err = publicKeyFromKeyCloak("http://localhost:1112/auth/realms/error")
	if err == nil {
		t.Error("invalid response handle")
	}

	// invalid KC host
	_, err = publicKeyFromKeyCloak("http://localhost:1113/auth/realms/error")
	if err == nil {
		t.Error("invalid response handle")
	}
}
