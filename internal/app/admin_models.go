package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/packs"
	"github.com/zcxads666/AegisLure/internal/profiles"
	"github.com/zcxads666/AegisLure/internal/security"
)

const maxInstanceModels = 64

func (a *App) adminInstanceModels(w http.ResponseWriter, r *http.Request, product string) {
	if r.Method == http.MethodGet {
		a.writeInstanceModels(w, product)
		return
	}
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-instance-models:"+product, 30, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 256*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "model configuration is too large"})
		return
	}
	var request struct {
		Models         []packs.ModelCatalogEntry `json:"models"`
		RestoreDefault bool                      `json:"restore_default"`
	}
	if err := decodeStrictValue(body, &request); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid model configuration"})
		return
	}
	target := "inst_" + product
	if request.RestoreDefault {
		if err := a.store.UnbindPack(model.PackKindModel, target); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "default model catalog restore failed"})
			return
		}
		a.invalidateProductCatalogSessions(product)
		a.recordAudit(r, "instance.models.restore_default", target, "success", nil)
		a.writeInstanceModels(w, product)
		return
	}
	if len(request.Models) == 0 || len(request.Models) > maxInstanceModels {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "models must contain between 1 and 64 entries"})
		return
	}
	entries := make([]packs.ModelCatalogEntry, len(request.Models))
	seenPublicIDs := make(map[string]bool, len(request.Models))
	for index, entry := range request.Models {
		entries[index] = normalizeInstanceModelEntry(a.cfg.InstanceKey, product, index, entry)
		publicID := entries[index].PublicModelID
		if publicID == "" || seenPublicIDs[publicID] {
			a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "public_model_id must be present and unique"})
			return
		}
		seenPublicIDs[publicID] = true
	}
	originPolicy := "open"
	if product == model.ProductNewAPI || product == model.ProductSub2API {
		originPolicy = "closed"
	}
	revision := fmt.Sprintf("instance-%d-%s", time.Now().UTC().UnixMilli(), security.MustRandomToken(3))
	document := packs.ModelCatalogPack{
		SchemaVersion: 1,
		Revision:      revision,
		Catalogs: []packs.ModelCatalog{{
			ID:           "instance-" + product,
			OriginPolicy: originPolicy,
			Products:     []string{product},
			Entries:      entries,
		}},
		SafetyContract: map[string]bool{"contains_endpoint": false, "contains_secret": false, "contains_download_url": false, "real_inference": false},
	}
	if err := packs.ValidateModelCatalogPack(document); err != nil {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	definition, err := json.Marshal(document)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "model configuration serialization failed"})
		return
	}
	packID := "instance-models-" + product
	previousRevision := ""
	if previous, ok := a.store.GetPack(model.PackKindModel, packID); ok {
		previousRevision = previous.Revision
	}
	pack := model.ConfigPack{ID: packID, Kind: model.PackKindModel, Revision: revision, PreviousRevision: previousRevision, Lifecycle: model.PackActive, Target: target, Definition: definition, Signature: security.Fingerprint(a.cfg.InstanceKey, string(definition))}
	if err := a.store.UpsertPack(pack); err != nil {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	if err := a.store.BindPack(model.PackKindModel, target, packID); err != nil {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	a.invalidateProductCatalogSessions(product)
	a.recordAudit(r, "instance.models.update", target, "success", map[string]string{"revision": revision, "model_count": fmt.Sprintf("%d", len(entries))})
	a.writeInstanceModels(w, product)
}

func normalizeInstanceModelEntry(instanceKey, product string, index int, entry packs.ModelCatalogEntry) packs.ModelCatalogEntry {
	entry.PublicModelID = strings.TrimSpace(entry.PublicModelID)
	entry.DisplayName = strings.TrimSpace(entry.DisplayName)
	entry.Provider = strings.TrimSpace(entry.Provider)
	entry.Origin = strings.TrimSpace(entry.Origin)
	entry.Status = strings.TrimSpace(entry.Status)
	if entry.ID == "" {
		entry.ID = "entry-" + security.Fingerprint(instanceKey, fmt.Sprintf("%s\x00%d\x00%s", product, index, entry.PublicModelID))[:20]
	}
	if entry.DisplayName == "" {
		entry.DisplayName = entry.PublicModelID
	}
	if entry.Provider == "" {
		entry.Provider = map[bool]string{true: "local", false: "provider"}[product != model.ProductNewAPI && product != model.ProductSub2API]
	}
	if entry.Origin == "" {
		entry.Origin = map[bool]string{true: "open", false: "closed"}[product != model.ProductNewAPI && product != model.ProductSub2API]
	}
	if len(entry.Capabilities) == 0 {
		entry.Capabilities = []string{"chat"}
	}
	if len(entry.Visibility) == 0 {
		entry.Visibility = []string{"guest", "user"}
	}
	if entry.Status == "" {
		entry.Status = "active"
	}
	return entry
}

func (a *App) writeInstanceModels(w http.ResponseWriter, product string) {
	entries, packID, revision, custom := a.configuredInstanceModelEntries(product)
	a.writeJSON(w, http.StatusOK, map[string]any{
		"product": product, "models": entries, "model_count": len(entries), "custom": custom,
		"pack_id": packID, "revision": revision, "surfaces": modelDisplaySurfaces(product),
		"self_hosted_fields": product == model.ProductVLLM || product == model.ProductOllama || product == model.ProductSGLang || product == model.ProductLocalAI,
		"max_models":         maxInstanceModels, "synthetic_only": true,
	})
}

func (a *App) configuredInstanceModelEntries(product string) ([]packs.ModelCatalogEntry, string, string, bool) {
	if pack, ok := a.store.BoundPack(model.PackKindModel, "inst_"+product); ok {
		var document packs.ModelCatalogPack
		if json.Unmarshal(pack.Definition, &document) == nil && packs.ValidateModelCatalogPack(document) == nil {
			entries := make([]packs.ModelCatalogEntry, 0)
			seen := make(map[string]bool)
			for _, catalog := range document.Catalogs {
				if !containsString(catalog.Products, product) {
					continue
				}
				for _, item := range catalog.Entries {
					resolved := catalogEntryFromPack(product, item, catalog.OriginPolicy)
					entry := adminModelEntry(a.cfg.InstanceKey, product, resolved)
					entry.ID = item.ID
					entry.Status = item.Status
					if entry.Status == "" {
						entry.Status = "active"
					}
					entries = append(entries, entry)
					seen[entry.PublicModelID] = true
				}
				for _, requested := range catalog.Models {
					if seen[requested] {
						continue
					}
					resolved, found := profiles.ResolveModel(product, requested)
					if !found {
						resolved = profiles.CatalogEntry{ID: requested, Object: "model", DisplayName: requested, Provider: "local", Origin: catalog.OriginPolicy, Capabilities: []string{"chat"}}
					}
					entries = append(entries, adminModelEntry(a.cfg.InstanceKey, product, resolved))
					seen[requested] = true
				}
			}
			return entries, pack.ID, pack.Revision, true
		}
	}
	catalog := profiles.Catalog(product)
	entries := make([]packs.ModelCatalogEntry, 0, len(catalog))
	for _, entry := range catalog {
		entries = append(entries, adminModelEntry(a.cfg.InstanceKey, product, entry))
	}
	return entries, "compiled-default", compiledCatalogRevision, false
}

func adminModelEntry(instanceKey, product string, entry profiles.CatalogEntry) packs.ModelCatalogEntry {
	return packs.ModelCatalogEntry{
		ID: "entry-" + security.Fingerprint(instanceKey, product+"\x00"+entry.ID)[:20], PublicModelID: entry.ID,
		DisplayName: entry.DisplayName, Provider: entry.Provider, Origin: entry.Origin,
		Capabilities: append([]string(nil), entry.Capabilities...), APIFamilies: append([]string(nil), entry.APIFamilies...),
		Visibility: append([]string(nil), entry.Visibility...), AuthRequirement: entry.AuthRequirement,
		VirtualContextTokens: entry.VirtualContextTokens, VirtualPriceProfile: entry.VirtualPriceProfile,
		Status: "active", Aliases: append([]string(nil), entry.Aliases...), ResponseTemplateSet: entry.ResponseTemplateSet,
		Architecture: entry.Architecture, Families: append([]string(nil), entry.Families...), ParameterSize: entry.ParameterSize,
		QuantizationLevel: entry.QuantizationLevel, ApproxSize: entry.ApproxSize,
	}
}

func modelDisplaySurfaces(product string) []string {
	return map[string][]string{
		model.ProductNewAPI:  {"控制台模型与定价页", "OpenAI /v1/models 与模型详情", "Anthropic 模型列表", "Gemini /v1beta/models", "调用响应与用量记录"},
		model.ProductVLLM:    {"OpenAI /v1/models", "聊天/补全/Responses 响应", "Prometheus model_name 指标", "Invocations 运行视图"},
		model.ProductOllama:  {"/api/tags 模型列表", "/api/ps 已加载模型", "/api/show 模型详情", "OpenAI /v1/models", "生成与聊天响应"},
		model.ProductSGLang:  {"OpenAI /v1/models", "聊天/补全/Responses 响应", "服务信息与调用记录"},
		model.ProductLocalAI: {"模型库 /models/available", "已安装模型与任务", "OpenAI /v1/models", "聊天/补全/Responses 响应"},
		model.ProductSub2API: {"模型广场", "可用渠道与密钥模型范围", "用户模型列表", "OpenAI /v1/models", "Codex /backend-api/codex/models", "调用响应与用量统计"},
	}[product]
}

func (a *App) invalidateProductCatalogSessions(product string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	removed := make(map[string]bool)
	for id, session := range a.sessions {
		if session.Product == product {
			delete(a.sessions, id)
			removed[id] = true
		}
	}
	for key, id := range a.anonymous {
		if removed[id] {
			delete(a.anonymous, key)
		}
	}
}
