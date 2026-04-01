package auth

import (
	"math"
	"strings"
	"time"
)

// Health tier constants.
const (
	HealthTierHealthy = "healthy"
	HealthTierWarm    = "warm"
	HealthTierRisky   = "risky"
	HealthTierBanned  = "banned"
)

// SchedulerBreakdown holds the per-factor contributions to the scheduler score.
type SchedulerBreakdown struct {
	UnauthorizedPenalty float64
	RateLimitPenalty    float64
	TimeoutPenalty      float64
	ServerPenalty       float64
	FailurePenalty      float64
	SuccessBonus        float64
	ProvenBonus         float64
	LatencyPenalty      float64
	SuccessRatePenalty  float64
}

// clampFloat constrains value to [min, max].
func clampFloat(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// linearDecay returns base * max(0, 1 - elapsed/window).
func linearDecay(base float64, elapsed, window time.Duration) float64 {
	if elapsed >= window || window <= 0 {
		return 0
	}
	return base * (1.0 - float64(elapsed)/float64(window))
}

// recordResultLocked records one request outcome into the sliding window.
func (a *Auth) recordResultLocked(success bool) {
	if success {
		a.RecentResults[a.RecentResultsIdx] = 1
	} else {
		a.RecentResults[a.RecentResultsIdx] = 0
	}
	a.RecentResultsIdx = (a.RecentResultsIdx + 1) % len(a.RecentResults)
	if a.RecentResultsCnt < len(a.RecentResults) {
		a.RecentResultsCnt++
	}
}

// recentSuccessRateLocked computes the sliding window success rate (0.0 ~ 1.0).
func (a *Auth) recentSuccessRateLocked() float64 {
	if a.RecentResultsCnt == 0 {
		return 1.0
	}
	var sum int
	for i := 0; i < a.RecentResultsCnt; i++ {
		sum += int(a.RecentResults[i])
	}
	return float64(sum) / float64(a.RecentResultsCnt)
}

// RecentSuccessRate computes the sliding window success rate (public accessor).
func (a *Auth) RecentSuccessRate() float64 {
	return a.recentSuccessRateLocked()
}

// SchedulerBreakdown returns the current score breakdown for observability.
func (a *Auth) SchedulerBreakdown() SchedulerBreakdown {
	return a.schedulerBreakdownLocked()
}

// recordLatencyLocked updates the exponential weighted moving average of latency.
func (a *Auth) recordLatencyLocked(latencyMs float64) {
	if latencyMs <= 0 {
		return
	}
	if a.LatencyEWMA == 0 {
		a.LatencyEWMA = latencyMs
		return
	}
	a.LatencyEWMA = a.LatencyEWMA*0.8 + latencyMs*0.2
}

// schedulerBreakdownLocked computes the per-factor score breakdown.
func (a *Auth) schedulerBreakdownLocked() SchedulerBreakdown {
	now := time.Now()
	d := SchedulerBreakdown{}

	if !a.LastUnauthorizedAt.IsZero() {
		d.UnauthorizedPenalty = linearDecay(50, now.Sub(a.LastUnauthorizedAt), 24*time.Hour)
	}
	if !a.LastRateLimitedAt.IsZero() {
		d.RateLimitPenalty = linearDecay(22, now.Sub(a.LastRateLimitedAt), time.Hour)
	}
	if !a.LastTimeoutAt.IsZero() {
		d.TimeoutPenalty = linearDecay(18, now.Sub(a.LastTimeoutAt), 15*time.Minute)
	}
	if !a.LastServerErrorAt.IsZero() {
		d.ServerPenalty = linearDecay(12, now.Sub(a.LastServerErrorAt), 15*time.Minute)
	}

	d.FailurePenalty = float64(clampInt(a.FailureStreak*6, 0, 24))
	d.SuccessBonus = float64(clampInt(a.SuccessStreak*2, 0, 12))

	if a.TotalRequests > 10 {
		d.ProvenBonus = 20
	}

	if a.RecentResultsCnt >= 5 {
		rate := a.recentSuccessRateLocked()
		switch {
		case rate < 0.5:
			d.SuccessRatePenalty = 15
		case rate < 0.75:
			d.SuccessRatePenalty = 8
		}
	}

	switch {
	case a.LatencyEWMA >= 12000:
		d.LatencyPenalty = 25
	case a.LatencyEWMA >= 8000:
		d.LatencyPenalty = 18
	case a.LatencyEWMA >= 4000:
		d.LatencyPenalty = 10
	case a.LatencyEWMA >= 2500:
		d.LatencyPenalty = 5
	}

	return d
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// concurrencyLimitForTier returns the dynamic concurrency limit based on health tier.
func concurrencyLimitForTier(baseLimit int64, tier string) int64 {
	if baseLimit <= 0 {
		baseLimit = 1
	}
	switch tier {
	case HealthTierHealthy:
		return baseLimit
	case HealthTierWarm:
		half := baseLimit / 2
		if half < 1 {
			return 1
		}
		return half
	case HealthTierRisky:
		return 1
	case HealthTierBanned:
		return 0
	default:
		if baseLimit >= 2 {
			return 2
		}
		return 1
	}
}

// RecomputeScheduler recalculates the health tier, scheduler score, and dynamic concurrency.
// baseConcurrency is the max concurrency for a healthy account (from config).
func (a *Auth) RecomputeScheduler(baseConcurrency int64) {
	now := time.Now()
	breakdown := a.schedulerBreakdownLocked()

	score := 100.0 -
		breakdown.UnauthorizedPenalty -
		breakdown.RateLimitPenalty -
		breakdown.TimeoutPenalty -
		breakdown.ServerPenalty -
		breakdown.FailurePenalty -
		breakdown.LatencyPenalty -
		breakdown.SuccessRatePenalty +
		breakdown.SuccessBonus +
		breakdown.ProvenBonus

	score = math.Max(score, 0)

	tier := HealthTierHealthy
	switch {
	case score < 60:
		tier = HealthTierRisky
	case score < 85:
		tier = HealthTierWarm
	}

	// Demote to warm if last failure is more recent than last success
	if a.LastFailureAt.After(a.LastSuccessAt) && !a.LastFailureAt.IsZero() && tier == HealthTierHealthy {
		tier = HealthTierWarm
	}
	// Demote to warm if recently unauthorized (within 24h)
	if !a.LastUnauthorizedAt.IsZero() && now.Sub(a.LastUnauthorizedAt) < 24*time.Hour && tier == HealthTierHealthy {
		tier = HealthTierWarm
	}
	// Preserve banned state
	if a.HealthTier == HealthTierBanned {
		tier = HealthTierBanned
	}

	a.HealthTier = tier
	a.SchedulerScore = score
	a.DynamicConcurrencyLimit = concurrencyLimitForTier(baseConcurrency, tier)

	// Auto-converge concurrency for slow accounts
	if a.LatencyEWMA >= 8000 && a.DynamicConcurrencyLimit > 1 {
		a.DynamicConcurrencyLimit = 1
	} else if a.LatencyEWMA >= 4000 && a.DynamicConcurrencyLimit > 2 {
		a.DynamicConcurrencyLimit = 2
	}
}

// RecordSuccess updates health signals after a successful request.
func (a *Auth) RecordSuccess(latencyMs float64) {
	a.SuccessStreak++
	a.FailureStreak = 0
	a.LastSuccessAt = time.Now()
	a.recordResultLocked(true)
	a.recordLatencyLocked(latencyMs)
	a.TotalRequests++
}

// RecordFailure updates health signals after a failed request.
func (a *Auth) RecordFailure(statusCode int, latencyMs float64) {
	a.FailureStreak++
	a.SuccessStreak = 0
	a.LastFailureAt = time.Now()
	a.recordResultLocked(false)
	a.recordLatencyLocked(latencyMs)
	a.TotalRequests++

	now := time.Now()
	switch {
	case statusCode == 401:
		a.LastUnauthorizedAt = now
	case statusCode == 429:
		a.LastRateLimitedAt = now
	case statusCode == 408 || statusCode == 504:
		a.LastTimeoutAt = now
	case statusCode >= 500:
		a.LastServerErrorAt = now
	}
}

// HealthTierPriority returns a numeric priority for sorting (higher = better).
func HealthTierPriority(tier string) int {
	switch tier {
	case HealthTierHealthy:
		return 4
	case HealthTierWarm:
		return 3
	case HealthTierRisky:
		return 2
	case HealthTierBanned:
		return 1
	default:
		return 0
	}
}

// IsProvider returns true if the auth's provider matches the given key (case-insensitive).
func (a *Auth) IsProvider(provider string) bool {
	return strings.EqualFold(strings.TrimSpace(a.Provider), strings.TrimSpace(provider))
}
