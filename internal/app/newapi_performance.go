package app

import (
	"net/http"
	"sort"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

const (
	newAPIPerformanceSeriesLimit = 120
	newAPIPerformanceRecentLimit = 12
)

type newAPIPerformanceSample struct {
	ts        int64
	latencyMS int64
	ttftMS    int64
	success   bool
	tps       float64
}

func newAPIPerformanceSamples(events []model.Event, modelName string, hours int, now time.Time) []newAPIPerformanceSample {
	if hours < 1 {
		hours = 24
	}
	cutoff := now.Add(-time.Duration(hours) * time.Hour)
	filtered := make([]model.Event, 0, len(events))
	for _, event := range events {
		if event.Product != model.ProductNewAPI || event.InvocationID == "" || event.ModelID == "" {
			continue
		}
		if modelName != "" && event.ModelID != modelName {
			continue
		}
		if event.ObservedAt.IsZero() || event.ObservedAt.Before(cutoff) {
			continue
		}
		filtered = append(filtered, event)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].ObservedAt.Equal(filtered[j].ObservedAt) {
			return filtered[i].Sequence < filtered[j].Sequence
		}
		return filtered[i].ObservedAt.Before(filtered[j].ObservedAt)
	})
	if len(filtered) > newAPIPerformanceSeriesLimit {
		filtered = filtered[len(filtered)-newAPIPerformanceSeriesLimit:]
	}

	samples := make([]newAPIPerformanceSample, 0, len(filtered))
	for _, event := range filtered {
		latencyMS := event.DurationMS
		if latencyMS <= 0 {
			latencyMS = 1
		}
		ttftMS := latencyMS / 2
		if ttftMS <= 0 {
			ttftMS = 1
		}
		tps := 0.0
		if event.SimulatedOutputTokens > 0 {
			tps = float64(event.SimulatedOutputTokens) * 1000 / float64(latencyMS)
		}
		samples = append(samples, newAPIPerformanceSample{
			ts:        event.ObservedAt.Unix(),
			latencyMS: latencyMS,
			ttftMS:    ttftMS,
			success:   event.Status >= http.StatusOK && event.Status < http.StatusMultipleChoices,
			tps:       tps,
		})
	}
	return samples
}

func newAPIPerformanceAggregate(samples []newAPIPerformanceSample) (float64, float64, float64, float64) {
	if len(samples) == 0 {
		return 0, 0, 0, 0
	}
	var latency, ttft, tps float64
	successes := 0
	for _, sample := range samples {
		latency += float64(sample.latencyMS)
		ttft += float64(sample.ttftMS)
		tps += sample.tps
		if sample.success {
			successes++
		}
	}
	count := float64(len(samples))
	return ttft / count, latency / count, float64(successes) * 100 / count, tps / count
}

func newAPIPerformanceRecentRates(samples []newAPIPerformanceSample) []int {
	start := 0
	if len(samples) > newAPIPerformanceRecentLimit {
		start = len(samples) - newAPIPerformanceRecentLimit
	}
	rates := make([]int, 0, len(samples)-start)
	for _, sample := range samples[start:] {
		if sample.success {
			rates = append(rates, 100)
		} else {
			rates = append(rates, 0)
		}
	}
	return rates
}

func newAPIPerformanceSummaryView(events []model.Event, hours int, now time.Time) map[string]any {
	byModel := make(map[string][]model.Event)
	for _, event := range events {
		if event.ModelID != "" {
			byModel[event.ModelID] = append(byModel[event.ModelID], event)
		}
	}
	modelNames := make([]string, 0, len(byModel))
	for modelName := range byModel {
		modelNames = append(modelNames, modelName)
	}
	sort.Strings(modelNames)

	models := make([]map[string]any, 0, len(modelNames))
	for _, modelName := range modelNames {
		samples := newAPIPerformanceSamples(byModel[modelName], modelName, hours, now)
		if len(samples) == 0 {
			continue
		}
		_, avgLatency, successRate, avgTPS := newAPIPerformanceAggregate(samples)
		models = append(models, map[string]any{
			"model_name":           modelName,
			"avg_latency_ms":       avgLatency,
			"success_rate":         successRate,
			"avg_tps":              avgTPS,
			"recent_success_rates": newAPIPerformanceRecentRates(samples),
			"request_count":        len(samples),
		})
	}
	return map[string]any{
		"success": true,
		"message": "",
		"data":    map[string]any{"models": models},
	}
}

func newAPIPerformanceDetailView(events []model.Event, modelName string, hours int, now time.Time) map[string]any {
	samples := newAPIPerformanceSamples(events, modelName, hours, now)
	groups := make([]map[string]any, 0, 1)
	if len(samples) > 0 {
		avgTTFT, avgLatency, successRate, avgTPS := newAPIPerformanceAggregate(samples)
		series := make([]map[string]any, 0, len(samples))
		for _, sample := range samples {
			pointSuccessRate := 0
			if sample.success {
				pointSuccessRate = 100
			}
			series = append(series, map[string]any{
				"ts":             sample.ts,
				"avg_ttft_ms":    float64(sample.ttftMS),
				"avg_latency_ms": float64(sample.latencyMS),
				"success_rate":   pointSuccessRate,
				"avg_tps":        sample.tps,
			})
		}
		groups = append(groups, map[string]any{
			"group":          "default",
			"avg_ttft_ms":    avgTTFT,
			"avg_latency_ms": avgLatency,
			"success_rate":   successRate,
			"avg_tps":        avgTPS,
			"series":         series,
		})
	}
	return map[string]any{
		"success": true,
		"message": "",
		"data": map[string]any{
			"model_name":    modelName,
			"series_schema": "event-sample-v1",
			"groups":        groups,
		},
	}
}
