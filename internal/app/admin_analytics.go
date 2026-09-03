package app

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

const dashboardRiskThreshold = 30

var dashboardShanghaiLocation = loadDashboardShanghaiLocation()

func loadDashboardShanghaiLocation() *time.Location {
	if location, err := time.LoadLocation(model.InteractionChainTimezone); err == nil {
		return location
	}
	// Asia/Shanghai has a stable UTC+08:00 offset. Keep the dashboard usable
	// in minimal containers that do not ship the IANA tzdata bundle.
	return time.FixedZone(model.InteractionChainTimezone, 8*60*60)
}

// dashboardTimeSeries builds calendar-aligned rolling windows. The last point
// is always the current hour/day, so the axis changes at the selected bucket
// boundary instead of staying on the same labels for a full window.
// risk_count intentionally uses the same medium-risk threshold as the rest
// of the admin console.
func dashboardTimeSeries(events []model.Event, now time.Time, bucketCount int, bucketSize time.Duration, labelFormat string) map[string]any {
	points := make([]map[string]any, 0, bucketCount)
	total := 0
	riskTotal := 0
	now = now.In(dashboardShanghaiLocation)
	if bucketCount <= 0 {
		return map[string]any{
			"bucket":         dashboardBucketName(bucketSize),
			"bucket_seconds": int(bucketSize / time.Second),
			"points":         points,
			"total":          0,
			"risk_total":     0,
			"risk_threshold": dashboardRiskThreshold,
			"timezone":       model.InteractionChainTimezone,
		}
	}

	currentStart := dashboardBucketStart(now, bucketSize)
	firstStart := dashboardAddBuckets(currentStart, bucketSize, -(bucketCount - 1))
	currentEnd := dashboardAddBuckets(currentStart, bucketSize, 1)
	for index := 0; index < bucketCount; index++ {
		start := dashboardAddBuckets(firstStart, bucketSize, index)
		end := dashboardAddBuckets(start, bucketSize, 1)
		count := 0
		riskCount := 0
		peakScore := 0
		for _, event := range events {
			if event.ObservedAt.Before(start) || !event.ObservedAt.Before(end) {
				continue
			}
			count++
			if event.Score >= dashboardRiskThreshold {
				riskCount++
			}
			if event.Score > peakScore {
				peakScore = event.Score
			}
		}
		total += count
		riskTotal += riskCount
		points = append(points, map[string]any{
			"key":        start.UTC().Format(time.RFC3339Nano),
			"label":      start.Format(labelFormat),
			"start_at":   start.UTC(),
			"end_at":     end.UTC(),
			"count":      count,
			"risk_count": riskCount,
			"peak_score": peakScore,
		})
	}
	return map[string]any{
		"bucket":          dashboardBucketName(bucketSize),
		"bucket_seconds":  int(bucketSize / time.Second),
		"points":          points,
		"total":           total,
		"risk_total":      riskTotal,
		"risk_threshold":  dashboardRiskThreshold,
		"timezone":        model.InteractionChainTimezone,
		"window_start_at": firstStart.UTC(),
		"window_end_at":   currentEnd.UTC(),
		"next_refresh_at": currentEnd.UTC(),
	}
}

func dashboardBucketStart(now time.Time, bucketSize time.Duration) time.Time {
	local := now.In(now.Location())
	year, month, day := local.Date()
	switch bucketSize {
	case time.Hour:
		return time.Date(year, month, day, local.Hour(), 0, 0, 0, local.Location())
	case 24 * time.Hour:
		return time.Date(year, month, day, 0, 0, 0, 0, local.Location())
	default:
		return local.Truncate(bucketSize)
	}
}

func dashboardAddBuckets(start time.Time, bucketSize time.Duration, count int) time.Time {
	if bucketSize == 24*time.Hour {
		return start.AddDate(0, 0, count)
	}
	return start.Add(time.Duration(count) * bucketSize)
}

func dashboardBucketName(bucketSize time.Duration) string {
	switch bucketSize {
	case time.Hour:
		return "hour"
	case 24 * time.Hour:
		return "day"
	default:
		return "custom"
	}
}

func (a *App) buildDashboardAnalytics(events []model.Event, indicators []model.Indicator, now time.Time) map[string]any {
	hour := dashboardTimeSeries(events, now, 24, time.Hour, "01/02 15:00")
	return map[string]any{
		"risk_activity": map[string]any{
			// day remains as a compatibility alias for older UI clients. New
			// clients should use hour/week/month explicitly.
			"hour":  hour,
			"day":   hour,
			"week":  dashboardTimeSeries(events, now, 7, 24*time.Hour, "01/02"),
			"month": dashboardTimeSeries(events, now, 30, 24*time.Hour, "01/02"),
		},
		"source_countries":          a.dashboardCountryShares(indicators),
		"honeypot_distribution":     dashboardHoneypotShares(events),
		"risk_trigger_distribution": dashboardRiskTriggerShares(events),
	}
}

func (a *App) dashboardCountryShares(indicators []model.Indicator) []map[string]any {
	rawIPs := make([]string, 0, len(indicators))
	seen := make(map[string]bool)
	for _, indicator := range indicators {
		if indicator.Score < dashboardRiskThreshold || seen[indicator.IP] {
			continue
		}
		seen[indicator.IP] = true
		rawIPs = append(rawIPs, indicator.IP)
	}
	locations := a.lookupIPInfo(rawIPs)
	counts := make(map[string]int)
	ipsByCountry := make(map[string]map[string]bool)
	metadataByCountry := make(map[string]ipInfoResult)
	total := 0
	for _, indicator := range indicators {
		if indicator.Score < dashboardRiskThreshold {
			continue
		}
		location, ok := locations[indicator.IP]
		if !ok {
			location = fallbackIPInfo(indicator.IP, "fallback_limit")
		}
		country := location.Country
		if country == "" {
			country = sourceCountryLabel(indicator.IP)
		}
		counts[country]++
		total++
		if ipsByCountry[country] == nil {
			ipsByCountry[country] = make(map[string]bool)
		}
		ipsByCountry[country][indicator.IP] = true
		if _, ok := metadataByCountry[country]; !ok {
			metadataByCountry[country] = location
		}
	}
	result := make([]map[string]any, 0, len(counts))
	for country, count := range counts {
		ips := make([]string, 0, len(ipsByCountry[country]))
		for ip := range ipsByCountry[country] {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		result = append(result, map[string]any{
			"key": country, "name": countryNameZH(metadataByCountry[country].CountryCode, country), "count": count,
			"percentage": sharePercentage(count, total), "ips": ips,
			"country_code":   metadataByCountry[country].CountryCode,
			"continent":      metadataByCountry[country].Continent,
			"continent_code": metadataByCountry[country].ContinentCode,
			"geo_source":     metadataByCountry[country].Source,
			"geo_status":     metadataByCountry[country].Status,
		})
	}
	sortShareList(result)
	return result
}

func dashboardHoneypotShares(events []model.Event) []map[string]any {
	counts := make(map[string]int)
	riskCounts := make(map[string]int)
	for _, event := range events {
		product := event.Product
		if product == "" {
			product = "unknown"
		}
		counts[product]++
		if event.Score >= dashboardRiskThreshold {
			riskCounts[product]++
		}
	}
	result := make([]map[string]any, 0, len(counts))
	total := len(events)
	for product, count := range counts {
		result = append(result, map[string]any{
			"key":          product,
			"name":         product,
			"count":        count,
			"percentage":   sharePercentage(count, total),
			"risk_count":   riskCounts[product],
			"risk_percent": sharePercentage(riskCounts[product], count),
		})
	}
	sortShareList(result)
	return result
}

func dashboardRiskTriggerShares(events []model.Event) []map[string]any {
	counts := map[string]int{"low": 0, "medium": 0, "high": 0}
	for _, event := range events {
		switch {
		case event.Score >= 60:
			counts["high"]++
		case event.Score >= dashboardRiskThreshold:
			counts["medium"]++
		default:
			counts["low"]++
		}
	}
	labels := []struct {
		key  string
		name string
	}{
		{key: "high", name: "高风险"},
		{key: "medium", name: "中风险"},
		{key: "low", name: "低风险"},
	}
	result := make([]map[string]any, 0, len(labels))
	for _, label := range labels {
		result = append(result, map[string]any{
			"key":        label.key,
			"name":       label.name,
			"count":      counts[label.key],
			"percentage": sharePercentage(counts[label.key], len(events)),
		})
	}
	return result
}

func sortShareList(items []map[string]any) {
	sort.Slice(items, func(i, j int) bool {
		left := items[i]["count"].(int)
		right := items[j]["count"].(int)
		if left != right {
			return left > right
		}
		return items[i]["name"].(string) < items[j]["name"].(string)
	})
}

func sharePercentage(count, total int) int {
	if count <= 0 || total <= 0 {
		return 0
	}
	return (count*100 + total/2) / total
}

// sourceCountryLabel is deliberately offline. AegisLure does not ship a
// GeoIP database, so it only classifies address ranges whose meaning is
// deterministic and leaves public addresses as unknown.
func sourceCountryLabel(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "未知"
	}
	if isDocumentationIP(ip) {
		return "文档地址"
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return "本地/保留"
	}
	return "未知"
}

func isDocumentationIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return (ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2) ||
			(ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100) ||
			(ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113)
	}
	return len(ip) == net.IPv6len && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8
}
