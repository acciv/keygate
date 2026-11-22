package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/acciv/keygate/internal/audit"
	"github.com/acciv/keygate/internal/config"
	"github.com/acciv/keygate/internal/policy"
	"github.com/acciv/keygate/internal/vault"
)

type Server struct {
	cfg      *config.Config
	vault    *vault.Vault
	audit    *audit.Log
	limiter  *limiter
	requests uint64
}

func New(cfg *config.Config) *Server {
	return &Server{
		cfg:     cfg,
		vault:   vault.New(cfg.Providers),
		audit:   audit.New(200),
		limiter: newLimiter(cfg.RatePerMinute),
	}
}

type bucket struct {
	tokens int
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int
}

func newLimiter(rate int) *limiter {
	if rate <= 0 {
		rate = 60
	}
	return &limiter{buckets: make(map[string]*bucket), rate: rate}
}

func (l *limiter) Allow(client string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[client]
	if !ok {
		b = &bucket{tokens: l.rate, last: now}
		l.buckets[client] = b
	}
	if now.Sub(b.last) >= time.Minute {
		b.tokens = l.rate
		b.last = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

type resolveRequest struct {
	Provider string `json:"provider"`
	Scope    string `json:"scope"`
	TTL      int    `json:"ttl"`
}

type rotateRequest struct {
	Provider string `json:"provider"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func clientID(r *http.Request) string {
	client := r.Header.Get("X-Client-ID")
	if client == "" {
		return "anonymous"
	}
	return client
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-KeyGate-Key") != s.cfg.MasterKey {
			s.audit.Add("auth_denied", clientID(r), "", "bad master key")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if !s.limiter.Allow(clientID(r)) {
			s.audit.Add("rate_limited", clientID(r), "", "too many requests")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
			return
		}
		next(w, r)
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/v1/keys/resolve", s.auth(s.resolve))
	mux.HandleFunc("/v1/keys/rotate", s.auth(s.rotate))
	mux.HandleFunc("/v1/audit", s.auth(s.auditList))
	mux.HandleFunc("/v1/providers", s.auth(s.providers))
	mux.HandleFunc("/v1/metrics", s.auth(s.metrics))
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"policy_version": policy.Version(),
		"time":           time.Now().UTC(),
	})
}

func (s *Server) resolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req resolveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}

	requestJSON := fmt.Sprintf(`{"provider":%q,"scope":%q,"ttl":%d}`, req.Provider, req.Scope, req.TTL)
	decision, err := policy.Evaluate(requestJSON, s.cfg.PolicyJSON())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.audit.Add("resolve", clientID(r), req.Provider, fmt.Sprintf("allow=%t", decision.Allow))
	if !decision.Allow {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"decision": decision,
			"error":    "denied by policy",
		})
		return
	}

	lease, err := s.vault.Issue(req.Provider, req.Scope, clientID(r), decision.EffectiveTTL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	masked, _ := s.vault.Masked(req.Provider)
	writeJSON(w, http.StatusOK, map[string]any{
		"lease":      lease.Token,
		"provider":   req.Provider,
		"scope":      req.Scope,
		"masked_key": masked,
		"expires_at": lease.ExpiresAt,
		"decision":   decision,
	})
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req rotateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	masked, err := s.vault.Rotate(req.Provider)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit.Add("rotate", clientID(r), req.Provider, "key rotated")
	writeJSON(w, http.StatusOK, map[string]any{
		"provider":   req.Provider,
		"masked_key": masked,
		"rotated_at": time.Now().UTC(),
	})
}

func (s *Server) auditList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": s.audit.List()})
}

func (s *Server) providers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"providers":     s.vault.Providers(),
		"active_leases": s.vault.ActiveLeases(),
	})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"policy_version": policy.Version(),
		"providers":      len(s.vault.Providers()),
		"active_leases":  s.vault.ActiveLeases(),
		"audit_events":   len(s.audit.List()),
	})
}

func (s *Server) ListenAndServe() error {
	log.Printf("keygate listening on %s (policy %s)", s.cfg.Addr, policy.Version())
	return http.ListenAndServe(s.cfg.Addr, s.Routes())
}
