package app

import (
	"errors"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/security"
)

const (
	newAPIRootUsername              = "root"
	newAPIRootPassword              = "123456"
	newAPIRootAccountClass          = "newapi-default-root"
	newAPIRootDefaultQuota    int64 = 100
	newAPIRegisteredUserQuota int64 = 10
	newAPIRootResetInterval         = 24 * time.Hour
	newAPIRootPasswordScore         = 25
	newAPIRootLoginScore            = 50
	newAPIRootLLMScore              = 100
)

func (a *App) ensureNewAPIRootAccount() error {
	if a == nil || a.cfg == nil || a.store == nil {
		return errors.New("New API root account dependencies are unavailable")
	}
	a.newAPIRootMu.Lock()
	defer a.newAPIRootMu.Unlock()

	now := time.Now().UTC()
	usernameFP := security.Fingerprint(a.cfg.InstanceKey, newAPIRootUsername)
	user, ok := a.store.FindHoneyUser(usernameFP)
	if !ok {
		return a.store.CreateHoneyUser(a.newAPIRootUser(now, a.newAPIRootUserID()))
	}
	if user.AccountClass != newAPIRootAccountClass || user.UsernameFP != usernameFP || user.ResetAt.IsZero() || !now.Before(user.ResetAt) {
		return a.resetNewAPIRootAccount(user, now)
	}
	return nil
}

func (a *App) newAPIRootUser(now time.Time, id string) model.HoneyUser {
	lengthBucket, passwordClasses, weakClass := passwordProfile(newAPIRootPassword)
	if id == "" {
		id = a.newAPIRootUserID()
	}
	return model.HoneyUser{
		ID:                   id,
		InstanceID:           a.cfg.InstanceID,
		UsernameFP:           security.Fingerprint(a.cfg.InstanceKey, newAPIRootUsername),
		UsernameHint:         security.RedactPreview(newAPIRootUsername, 3),
		PasswordFP:           security.Fingerprint(a.cfg.InstanceKey, newAPIRootPassword),
		PasswordLengthBucket: lengthBucket,
		PasswordClasses:      passwordClasses,
		PasswordWeakClass:    weakClass,
		VirtualQuota:         newAPIRootDefaultQuota,
		CreatedAt:            now,
		LastSeen:             now,
		AccountClass:         newAPIRootAccountClass,
		ResetAt:              now.Add(newAPIRootResetInterval),
	}
}

func (a *App) newAPIRootUserID() string {
	return "hu_root_" + security.Fingerprint(a.cfg.InstanceKey, "newapi-special-root")[:16]
}

func (a *App) resetNewAPIRootAccount(current model.HoneyUser, now time.Time) error {
	reset := a.newAPIRootUser(now, current.ID)
	if current.InstanceID != "" {
		reset.InstanceID = current.InstanceID
	}
	oldTokens := a.store.ListTokens(current.ID)
	if err := a.store.ResetHoneyUser(reset); err != nil {
		return err
	}
	for _, token := range oldTokens {
		a.forgetNewAPIRawKey(token.ID)
	}
	a.clearAllSessionUsers(current.ID)
	return nil
}

func (a *App) isNewAPIRootUser(user model.HoneyUser) bool {
	return user.AccountClass == newAPIRootAccountClass && user.UsernameFP == security.Fingerprint(a.cfg.InstanceKey, newAPIRootUsername)
}

func (a *App) isNewAPIRootUserID(userID string) bool {
	if userID == "" {
		return false
	}
	user, ok := a.store.GetHoneyUser(userID)
	return ok && a.isNewAPIRootUser(user)
}

func markNewAPIRootMonitoring(obs *Observation, phase string, score int, reason string) {
	annotateNewAPIRootMonitoring(obs, phase, reason)
	if obs == nil {
		return
	}
	obs.ScoreOverride = &score
}

func annotateNewAPIRootMonitoring(obs *Observation, phase, reason string) {
	if obs == nil {
		return
	}
	if obs.Metadata == nil {
		obs.Metadata = make(map[string]string)
	}
	obs.Metadata["special_account"] = newAPIRootUsername
	obs.Metadata["root_monitoring_phase"] = phase
	if reason != "" {
		obs.ExtraReasons = append(obs.ExtraReasons, reason)
	}
}
