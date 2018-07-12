// Copyright 2018 Kodix LLC. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rsa"
	"sync"
)

// keyCache - local storage of RSA PublicKeys for given issuers
type keyCache struct {
	mu   sync.RWMutex
	data map[string]*rsa.PublicKey
}

func newKeyCache() *keyCache {
	return &keyCache{
		data: make(map[string]*rsa.PublicKey),
	}
}

func (kc *keyCache) Set(key string, val *rsa.PublicKey) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	kc.set(key, val)
}

// Clear removes all cached keys
func (kc *keyCache) Clear() {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	kc.clear()
}

func (kc *keyCache) Get(key string) (*rsa.PublicKey, bool) {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	return kc.get(key)
}

func (kc *keyCache) Count() int {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	return kc.count()
}

func (kc *keyCache) set(key string, val *rsa.PublicKey) {
	kc.data[key] = val
}

func (kc *keyCache) clear() {
	kc.data = make(map[string]*rsa.PublicKey)
}

func (kc *keyCache) get(key string) (*rsa.PublicKey, bool) {
	v, ok := kc.data[key]
	return v, ok
}

func (kc *keyCache) count() int {
	return len(kc.data)
}
