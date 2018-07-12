// Copyright 2018 Kodix LLC. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rsa"
	"reflect"
	"testing"
)

func Test_keyCache_Set(t *testing.T) {
	pk := &rsa.PublicKey{}
	type args struct {
		key string
		val *rsa.PublicKey
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"usual",
			args{
				"test",
				pk,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := newKeyCache()
			kc.Set(tt.args.key, tt.args.val)
			if v, ok := kc.data["test"]; !ok || v != pk {
				t.Errorf("Setter error")
			}
			if _, ok := kc.data["qwerty"]; ok {
				t.Errorf("Setter error")
			}
		})
	}
}

func Test_keyCache_Clear(t *testing.T) {
	data := map[string]*rsa.PublicKey{
		"test1": {},
		"test2": {},
		"test3": {},
		"test4": {},
		"test5": {},
	}
	t.Run("usual", func(t *testing.T) {
		kc := &keyCache{
			data: data,
		}
		kc.Clear()
		if len(kc.data) > 0 {
			t.Errorf("Clear error")
		}
	})
}

func Test_keyCache_Get(t *testing.T) {
	pk := &rsa.PublicKey{}
	type args struct {
		key string
	}
	tests := []struct {
		name  string
		args  args
		want  *rsa.PublicKey
		want1 bool
	}{
		{
			"exists",
			args{"test"},
			pk,
			true,
		},
		{
			"not exists",
			args{"qwerty"},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := newKeyCache()
			kc.data["test"] = pk
			got, got1 := kc.Get(tt.args.key)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("keyCache.Get() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("keyCache.Get() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_keyCache_Count(t *testing.T) {
	type fields struct {
		data map[string]*rsa.PublicKey
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{
			"",
			fields{},
			0,
		},
		{
			"",
			fields{
				data: map[string]*rsa.PublicKey{
					"test_1": nil,
					"test_2": nil,
					"test_3": nil,
					"test_4": nil,
				},
			},
			4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := &keyCache{
				data: tt.fields.data,
			}
			if got := kc.Count(); got != tt.want {
				t.Errorf("keyCache.Count() = %v, want %v", got, tt.want)
			}
		})
	}
}
