package app

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/packs"
	"github.com/zcxads666/AegisLure/internal/profiles"
)

const compiledCatalogRevision = "compiled-default"

// applyRuntimePacks resolves the active local bindings at request time. A
// draft pack is therefore inert, and a failed or malformed persisted binding
// falls back to the compiled safe profile rather than taking a listener down.
func (a *App) applyRuntimePacks(profile profiles.Profile) profiles.Profile {
	return a.applyRuntimePacksForSession(profile, Session{})
}

func (a *App) applyRuntimePacksForSession(profile profiles.Profile, session Session) profiles.Profile {
	if a.store == nil {
		return profile
	}
	target := "inst_" + profile.Product
	if pack, ok := a.store.BoundPack(model.PackKindFingerprint, target); ok {
		var document packs.FingerprintPackDocument
		if packs.ValidateDefinition("fingerprint", pack.Definition) == nil && json.Unmarshal(pack.Definition, &document) == nil {
			for _, item := range document.Packs {
				if item.Product == profile.Product {
					profile.ID = item.ID
					profile.DisplayVersion = item.DisplayVersion
					break
				}
			}
		}
	}
	if pack, ok := a.store.BoundPack(model.PackKindScenario, target); ok {
		var document packs.ScenarioPackDocument
		if packs.ValidateDefinition("scenario", pack.Definition) == nil && json.Unmarshal(pack.Definition, &document) == nil {
			for _, item := range document.Packs {
				if item.Product != profile.Product {
					continue
				}
				if item.AuthPosture != "" {
					profile.Scenario = item.AuthPosture
				}
				if item.EffectScope != "" {
					profile.EffectScope = item.EffectScope
				}
				if item.EffectTTLSec > 0 {
					profile.EffectTTL = time.Duration(item.EffectTTLSec) * time.Second
				}
				break
			}
		}
	}
	switch profile.Product {
	case model.ProductVLLM:
		profile.Persona.VLLM = a.vllmPersonaForSession(profile, session)
	case model.ProductOllama:
		profile.Persona.Ollama = a.ollamaPersonaForSession(profile, session)
	}
	return profile
}

func (a *App) catalogFor(product string) []profiles.CatalogEntry {
	return a.catalogForAudienceRevision(product, "guest", "")
}

func (a *App) catalogForAudience(product, audience string) []profiles.CatalogEntry {
	return a.catalogForAudienceRevision(product, audience, "")
}

func (a *App) catalogForSession(product, audience string, session Session) []profiles.CatalogEntry {
	revision := ""
	if session.CatalogRevisions != nil {
		revision = session.CatalogRevisions[product]
	}
	return a.catalogForAudienceRevision(product, audience, revision)
}

func (a *App) catalogForAudienceRevision(product, audience, revision string) []profiles.CatalogEntry {
	fallback := profiles.Catalog(product)
	if a.store == nil {
		return fallback
	}
	if revision == compiledCatalogRevision {
		return fallback
	}
	var pack model.ConfigPack
	var ok bool
	if strings.TrimSpace(revision) != "" {
		pack, ok = a.store.FindPackRevision(model.PackKindModel, revision)
	} else {
		pack, ok = a.store.BoundPack(model.PackKindModel, "inst_"+product)
	}
	if !ok {
		return fallback
	}
	var document packs.ModelCatalogPack
	if packs.ValidateDefinition(model.PackKindModel, pack.Definition) != nil || json.Unmarshal(pack.Definition, &document) != nil || packs.ValidateModelCatalogPack(document) != nil {
		return fallback
	}
	result := make([]profiles.CatalogEntry, 0)
	seen := make(map[string]bool)
	matchedProduct := false
	for _, catalog := range document.Catalogs {
		if !containsString(catalog.Products, product) {
			continue
		}
		matchedProduct = true
		for _, item := range catalog.Entries {
			if item.Status == "disabled" || !modelEntryVisible(item.Visibility, audience) {
				continue
			}
			entry := catalogEntryFromPack(product, item, catalog.OriginPolicy)
			if entry.ID != "" && !seen[entry.ID] {
				seen[entry.ID] = true
				result = append(result, entry)
			}
		}
		for _, requested := range catalog.Models {
			entry, resolved := profiles.ResolveModel(product, requested)
			if !resolved {
				entry = profiles.CatalogEntry{
					ID:           requested,
					Object:       "model",
					DisplayName:  requested,
					Provider:     "local",
					Origin:       catalog.OriginPolicy,
					Capabilities: []string{"chat"},
				}
			} else {
				entry = cloneCatalogEntry(entry)
				entry.Origin = catalog.OriginPolicy
			}
			if !seen[entry.ID] {
				seen[entry.ID] = true
				result = append(result, entry)
			}
		}
	}
	if len(result) == 0 && !matchedProduct {
		return fallback
	}
	return result
}

func modelEntryVisible(visibility []string, audience string) bool {
	if len(visibility) == 0 {
		return true
	}
	for _, value := range visibility {
		if value == audience {
			return true
		}
	}
	return false
}

func catalogEntryFromPack(product string, item packs.ModelCatalogEntry, originPolicy string) profiles.CatalogEntry {
	publicID := strings.TrimSpace(item.PublicModelID)
	if publicID == "" {
		publicID = strings.TrimSpace(item.ID)
	}
	entry, resolved := profiles.ResolveModel(product, publicID)
	if !resolved {
		for _, alias := range item.Aliases {
			if candidate, ok := profiles.ResolveModel(product, alias); ok {
				entry = candidate
				resolved = true
				break
			}
		}
	}
	if resolved {
		entry = cloneCatalogEntry(entry)
	} else {
		entry = profiles.CatalogEntry{Object: "model"}
	}
	entry.ID = publicID
	entry.Object = "model"
	entry.DisplayName = item.DisplayName
	entry.Provider = item.Provider
	entry.Origin = item.Origin
	if entry.Origin == "" {
		entry.Origin = originPolicy
	}
	entry.Capabilities = append([]string(nil), item.Capabilities...)
	entry.APIFamilies = append([]string(nil), item.APIFamilies...)
	entry.Visibility = append([]string(nil), item.Visibility...)
	entry.AuthRequirement = item.AuthRequirement
	entry.VirtualContextTokens = item.VirtualContextTokens
	entry.VirtualPriceProfile = item.VirtualPriceProfile
	entry.ResponseTemplateSet = item.ResponseTemplateSet
	entry.Aliases = append([]string(nil), item.Aliases...)
	return entry
}

func (a *App) vllmPersonaFor(profile profiles.Profile) profiles.VLLMPersonaProfile {
	return a.vllmPersonaForSession(profile, Session{})
}

func (a *App) vllmPersonaForSession(profile profiles.Profile, session Session) profiles.VLLMPersonaProfile {
	persona := profile.Persona.VLLM
	if _, ok := a.store.BoundPack(model.PackKindModel, "inst_"+profile.Product); !ok {
		return persona
	}
	catalog := a.catalogForSession(profile.Product, "guest", session)
	if len(catalog) == 0 {
		return persona
	}
	served := make([]string, 0, len(catalog)*2)
	seen := make(map[string]bool)
	for _, entry := range catalog {
		for _, name := range append([]string{entry.ID}, entry.Aliases...) {
			name = strings.TrimSpace(name)
			if name != "" && !seen[name] {
				seen[name] = true
				served = append(served, name)
			}
		}
	}
	if len(served) > 0 {
		persona.Model = catalog[0].ID
		persona.ServedModelNames = served
	}
	return persona
}

func (a *App) ollamaPersonaFor(profile profiles.Profile) profiles.OllamaPersonaConfig {
	return a.ollamaPersonaForSession(profile, Session{})
}

func (a *App) ollamaPersonaForSession(profile profiles.Profile, session Session) profiles.OllamaPersonaConfig {
	persona := profile.Persona.Ollama
	if _, ok := a.store.BoundPack(model.PackKindModel, "inst_"+profile.Product); !ok {
		return persona
	}
	catalog := a.catalogForSession(profile.Product, "guest", session)
	if len(catalog) == 0 {
		return persona
	}
	models := make([]profiles.OllamaModelProfile, 0, len(catalog))
	for _, entry := range catalog {
		family := entry.Architecture
		if family == "" && len(entry.Families) > 0 {
			family = entry.Families[0]
		}
		if family == "" {
			family = "llama"
		}
		families := append([]string(nil), entry.Families...)
		if len(families) == 0 {
			families = []string{family}
		}
		publicName := entry.ID
		if len(entry.Aliases) > 0 && strings.TrimSpace(entry.Aliases[0]) != "" {
			publicName = entry.Aliases[0]
		}
		parameterSize := entry.ParameterSize
		if parameterSize == "" {
			parameterSize = "unknown"
		}
		quantization := entry.QuantizationLevel
		if quantization == "" {
			quantization = "Q4_K_M"
		}
		size := entry.ApproxSize
		if size <= 0 {
			size = 1 << 30
		}
		models = append(models, profiles.OllamaModelProfile{
			CanonicalName:     entry.ID,
			Name:              publicName,
			Model:             publicName,
			Aliases:           append([]string(nil), entry.Aliases...),
			Family:            family,
			Families:          families,
			Format:            "gguf",
			ParameterSize:     parameterSize,
			QuantizationLevel: quantization,
			Size:              size,
		})
	}
	persona.ModelCatalog = models
	return persona
}

func cloneCatalogEntry(entry profiles.CatalogEntry) profiles.CatalogEntry {
	entry.Capabilities = append([]string(nil), entry.Capabilities...)
	entry.Aliases = append([]string(nil), entry.Aliases...)
	entry.APIFamilies = append([]string(nil), entry.APIFamilies...)
	entry.Visibility = append([]string(nil), entry.Visibility...)
	entry.Families = append([]string(nil), entry.Families...)
	return entry
}

func (a *App) resolveCatalogModelForAudience(product, requested, audience string) (profiles.CatalogEntry, bool) {
	return a.resolveCatalogModelForAudienceRevision(product, requested, audience, "")
}

func (a *App) resolveCatalogModelForSession(product, requested, audience string, session Session) (profiles.CatalogEntry, bool) {
	revision := ""
	if session.CatalogRevisions != nil {
		revision = session.CatalogRevisions[product]
	}
	return a.resolveCatalogModelForAudienceRevision(product, requested, audience, revision)
}

func (a *App) resolveCatalogModelForAudienceRevision(product, requested, audience, revision string) (profiles.CatalogEntry, bool) {
	requested = strings.TrimSpace(requested)
	for _, entry := range a.catalogForAudienceRevision(product, audience, revision) {
		if entry.ID == requested {
			return entry, true
		}
		for _, alias := range entry.Aliases {
			if alias == requested {
				return entry, true
			}
		}
	}
	return profiles.CatalogEntry{}, false
}

func virtualEffectOwner(profile profiles.Profile, session Session) (scope, ownerKey string, ttl time.Duration) {
	scope = strings.TrimSpace(profile.EffectScope)
	if scope != "session" && scope != "actor" && scope != "virtual_tenant" {
		scope = "session"
	}
	ownerKey = session.ID
	if scope != "session" && session.UserID != "" {
		ownerKey = session.UserID
	}
	ttl = profile.EffectTTL
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = 90 * time.Second
	}
	return scope, ownerKey, ttl
}
