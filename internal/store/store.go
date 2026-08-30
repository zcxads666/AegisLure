package store

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/model"
)

type Store struct {
	mu       sync.RWMutex
	dir      string
	key      string
	state    model.State
	eventSeq uint64
}

func Open(dir, key string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, key: key}
	s.state = model.State{
		HoneyUsers:  make(map[string]model.HoneyUser),
		HoneyTokens: make(map[string]model.HoneyToken),
		Effects:     make(map[string]model.VirtualEffect),
		Quotas:      make(map[string]int64),
	}
	path := filepath.Join(dir, "state.json")
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &s.state); err != nil {
			return nil, fmt.Errorf("decode state: %w", err)
		}
		s.ensureMaps()
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := s.loadEventSequence(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) loadEventSequence() error {
	f, err := os.Open(filepath.Join(s.dir, "events.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	var line uint64
	for scanner.Scan() {
		line++
		var event model.Event
		if json.Unmarshal(scanner.Bytes(), &event) == nil && event.Sequence > s.eventSeq {
			s.eventSeq = event.Sequence
		} else if event.Sequence == 0 && line > s.eventSeq {
			s.eventSeq = line
		}
	}
	return scanner.Err()
}

func (s *Store) ensureMaps() {
	if s.state.HoneyUsers == nil {
		s.state.HoneyUsers = make(map[string]model.HoneyUser)
	}
	if s.state.HoneyTokens == nil {
		s.state.HoneyTokens = make(map[string]model.HoneyToken)
	}
	if s.state.Effects == nil {
		s.state.Effects = make(map[string]model.VirtualEffect)
	}
	if s.state.Quotas == nil {
		s.state.Quotas = make(map[string]int64)
	}
	if s.state.QuotaLedger == nil {
		s.state.QuotaLedger = []model.QuotaEntry{}
	}
}

func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, "state.json.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, "state.json"))
}

func (s *Store) Update(fn func(*model.State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMaps()
	if err := fn(&s.state); err != nil {
		return err
	}
	return s.saveLocked()
}

func (s *Store) Admin() model.AdminState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Admin
}

func (s *Store) CreateHoneyUser(user model.HoneyUser) error {
	return s.Update(func(state *model.State) error {
		for _, existing := range state.HoneyUsers {
			if existing.UsernameFP == user.UsernameFP {
				return errors.New("honey username already exists")
			}
		}
		state.HoneyUsers[user.ID] = user
		state.Quotas[user.ID] = user.VirtualQuota
		return nil
	})
}

func (s *Store) FindHoneyUser(usernameFP string) (model.HoneyUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.state.HoneyUsers {
		if user.UsernameFP == usernameFP {
			return user, true
		}
	}
	return model.HoneyUser{}, false
}

func (s *Store) GetHoneyUser(id string) (model.HoneyUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.state.HoneyUsers[id]
	return user, ok
}

func (s *Store) TouchHoneyUser(id string, update func(*model.HoneyUser)) error {
	return s.Update(func(state *model.State) error {
		user, ok := state.HoneyUsers[id]
		if !ok {
			return errors.New("honey user not found")
		}
		update(&user)
		state.HoneyUsers[id] = user
		state.Quotas[id] = user.VirtualQuota
		return nil
	})
}

func (s *Store) AddToken(token model.HoneyToken) error {
	return s.Update(func(state *model.State) error {
		state.HoneyTokens[token.ID] = token
		return nil
	})
}

func (s *Store) FindToken(hash string) (model.HoneyToken, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, token := range s.state.HoneyTokens {
		if token.Hash == hash && token.DisabledAt.IsZero() {
			return token, true
		}
	}
	return model.HoneyToken{}, false
}

func (s *Store) AddQuota(userID string, amount int64) (int64, error) {
	return s.applyQuota(userID, "adjustment", "", "", amount)
}

func (s *Store) ConsumeQuota(userID, tokenID, invocationID string, amount int64) (int64, error) {
	if amount < 0 {
		return 0, errors.New("quota cost must be non-negative")
	}
	return s.applyQuota(userID, "invocation", tokenID, invocationID, -amount)
}

func (s *Store) applyQuota(userID, entryType, tokenID, invocationID string, amount int64) (int64, error) {
	var balance int64
	err := s.Update(func(state *model.State) error {
		user, ok := state.HoneyUsers[userID]
		if !ok {
			return errors.New("honey user not found")
		}
		if amount > 0 && user.VirtualQuota > math.MaxInt64-amount {
			return errors.New("virtual quota overflow")
		}
		if amount < 0 {
			if amount == math.MinInt64 || user.VirtualQuota < -amount {
				return errors.New("insufficient virtual quota")
			}
		}
		user.VirtualQuota += amount
		state.HoneyUsers[userID] = user
		state.Quotas[userID] = user.VirtualQuota
		balance = user.VirtualQuota
		state.QuotaLedger = append(state.QuotaLedger, model.QuotaEntry{ID: fmt.Sprintf("ql_%d", len(state.QuotaLedger)+1), HoneyUserID: userID, TokenID: tokenID, InvocationID: invocationID, EntryType: entryType, Amount: amount, BalanceAfter: balance, CreatedAt: time.Now().UTC()})
		return nil
	})
	return balance, err
}

func (s *Store) AddEffect(effect model.VirtualEffect) error {
	return s.Update(func(state *model.State) error {
		state.Effects[effect.ID] = effect
		return nil
	})
}

func (s *Store) ActiveEffects(ownerKey, product string, now time.Time) []model.VirtualEffect {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var effects []model.VirtualEffect
	for _, effect := range s.state.Effects {
		if effect.OwnerKey == ownerKey && effect.Product == product && effect.ExpiresAt.After(now) {
			effects = append(effects, effect)
		}
	}
	return effects
}

// MarkEffectsVerified records that a later request observed a virtual effect.
// It never changes a listener, process, host, or any other owner's state.
func (s *Store) MarkEffectsVerified(ownerKey, product, effectType string, now time.Time) int {
	verified := 0
	_ = s.Update(func(state *model.State) error {
		for id, effect := range state.Effects {
			if effect.OwnerKey != ownerKey || effect.Product != product || effect.EffectType != effectType || !effect.ExpiresAt.After(now) {
				continue
			}
			if effect.VerifiedAt.IsZero() {
				effect.VerifiedAt = now
				state.Effects[id] = effect
				verified++
			}
		}
		return nil
	})
	return verified
}

func (s *Store) AppendEvent(event model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventSeq++
	event.Sequence = s.eventSeq
	path := filepath.Join(s.dir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(event); err != nil {
		return err
	}
	return f.Sync()
}

func (s *Store) Events(limit int, product, sourceIP string) ([]model.Event, error) {
	if limit == 0 || limit > 1000 {
		limit = 100
	}
	path := filepath.Join(s.dir, "events.jsonl")
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []model.Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []model.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		var event model.Event
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			continue
		}
		if product != "" && event.Product != product {
			continue
		}
		if sourceIP != "" && event.SourceIP != sourceIP {
			continue
		}
		all = append(all, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all, nil
}

func (s *Store) Indicators() ([]model.Indicator, error) {
	events, err := s.Events(-1, "", "")
	if err != nil {
		return nil, err
	}
	type aggregate struct {
		item    model.Indicator
		prod    map[string]bool
		reasons map[string]bool
	}
	byIP := make(map[string]*aggregate)
	for _, event := range events {
		if event.SourceIP == "" {
			continue
		}
		a := byIP[event.SourceIP]
		if a == nil {
			a = &aggregate{item: model.Indicator{IP: event.SourceIP, FirstSeen: event.ObservedAt, LastSeen: event.ObservedAt}, prod: map[string]bool{}, reasons: map[string]bool{}}
			byIP[event.SourceIP] = a
		}
		if event.ObservedAt.Before(a.item.FirstSeen) {
			a.item.FirstSeen = event.ObservedAt
		}
		if event.ObservedAt.After(a.item.LastSeen) {
			a.item.LastSeen = event.ObservedAt
		}
		if event.Score > a.item.Score {
			a.item.Score = event.Score
		}
		a.item.EvidenceCount++
		a.prod[event.Product] = true
		for _, reason := range event.ReasonCodes {
			a.reasons[reason] = true
		}
	}
	result := make([]model.Indicator, 0, len(byIP))
	for _, a := range byIP {
		for product := range a.prod {
			a.item.Products = append(a.item.Products, product)
		}
		for reason := range a.reasons {
			a.item.ReasonCodes = append(a.item.ReasonCodes, reason)
		}
		sort.Strings(a.item.Products)
		sort.Strings(a.item.ReasonCodes)
		a.item.Confidence = confidenceForScore(a.item.Score)
		a.item.ExpiresAt = a.item.LastSeen.Add(ttlForScore(a.item.Score))
		switch {
		case a.item.Score >= 80:
			a.item.RecommendedAction = "temporary_block"
		case a.item.Score >= 60:
			a.item.RecommendedAction = "review_and_block_24h"
		case a.item.Score >= 40:
			a.item.RecommendedAction = "observe_or_block_6h"
		default:
			a.item.RecommendedAction = "observe"
		}
		result = append(result, a.item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Score > result[j].Score })
	return result, nil
}

func confidenceForScore(score int) string {
	if score >= 60 {
		return "high"
	}
	if score >= 30 {
		return "medium"
	}
	return "low"
}

func ttlForScore(score int) time.Duration {
	if score >= 80 {
		return 7 * 24 * time.Hour
	}
	if score >= 60 {
		return 24 * time.Hour
	}
	return 6 * time.Hour
}

func (s *Store) Export(format string, minScore int) (string, string, error) {
	items, err := s.Indicators()
	if err != nil {
		return "", "", err
	}
	filtered := items[:0]
	for _, item := range items {
		if item.Score >= minScore {
			filtered = append(filtered, item)
		}
	}
	items = filtered
	var data []byte
	switch strings.ToLower(format) {
	case "plain", "txt":
		var lines []string
		for _, item := range items {
			lines = append(lines, item.IP)
		}
		data = []byte(strings.Join(lines, "\n") + "\n")
	case "csv":
		var builder strings.Builder
		writer := csv.NewWriter(&builder)
		if err := writer.Write([]string{"ip", "score", "confidence", "first_seen", "last_seen", "reason_codes"}); err != nil {
			return "", "", err
		}
		for _, item := range items {
			if err := writer.Write([]string{item.IP, fmt.Sprintf("%d", item.Score), item.Confidence, item.FirstSeen.Format(time.RFC3339), item.LastSeen.Format(time.RFC3339), strings.Join(item.ReasonCodes, "|")}); err != nil {
				return "", "", err
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return "", "", err
		}
		data = []byte(builder.String())
	case "json", "":
		data, err = json.MarshalIndent(items, "", "  ")
		if err != nil {
			return "", "", err
		}
	default:
		return "", "", fmt.Errorf("unsupported export format %q", format)
	}
	return string(data), fmt.Sprintf("%x", config.KeyedHash(s.key, string(data))), nil
}
