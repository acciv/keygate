package vault

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Lease struct {
	Token     string    `json:"lease"`
	Provider  string    `json:"provider"`
	Scope     string    `json:"scope"`
	Client    string    `json:"client"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Vault struct {
	mu     sync.RWMutex
	keys   map[string]string
	leases map[string]Lease
}

func New(providers map[string]string) *Vault {
	keys := make(map[string]string, len(providers))
	for name, key := range providers {
		keys[name] = key
	}
	return &Vault{keys: keys, leases: make(map[string]Lease)}
}

func randomHex(bytesCount int) string {
	buf := make([]byte, bytesCount)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("fallback%p", &buf)
	}
	return hex.EncodeToString(buf)
}

func Mask(value string) string {
	if len(value) <= 8 {
		return "****"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

func (v *Vault) Issue(provider, scope, client string, ttl int) (Lease, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.keys[provider]; !ok {
		return Lease{}, fmt.Errorf("unknown provider: %s", provider)
	}
	lease := Lease{
		Token:     "kg_lease_" + randomHex(12),
		Provider:  provider,
		Scope:     scope,
		Client:    client,
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	v.leases[lease.Token] = lease
	return lease, nil
}

func (v *Vault) Rotate(provider string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.keys[provider]; !ok {
		return "", fmt.Errorf("unknown provider: %s", provider)
	}
	newKey := "ROTATED_" + randomHex(12)
	v.keys[provider] = newKey
	return Mask(newKey), nil
}

func (v *Vault) Masked(provider string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok := v.keys[provider]
	if !ok {
		return "", false
	}
	return Mask(key), true
}

func (v *Vault) Providers() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	names := make([]string, 0, len(v.keys))
	for name := range v.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (v *Vault) ActiveLeases() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	now := time.Now()
	count := 0
	for _, lease := range v.leases {
		if lease.ExpiresAt.After(now) {
			count++
		}
	}
	return count
}
