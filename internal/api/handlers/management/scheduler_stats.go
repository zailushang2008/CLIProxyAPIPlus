package management

import (
	"net/http"
	"sort"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"

	"github.com/gin-gonic/gin"
)

// AuthHealthSnapshot represents the health status of a single auth entry.
type AuthHealthSnapshot struct {
	ID                      string                `json:"id"`
	Provider                string                `json:"provider"`
	HealthTier              string                `json:"health_tier"`
	SchedulerScore          float64               `json:"scheduler_score"`
	DynamicConcurrencyLimit int64                 `json:"dynamic_concurrency_limit"`
	ActiveRequests          int64                 `json:"active_requests"`
	TotalRequests           int64                 `json:"total_requests"`
	SuccessStreak           int                   `json:"success_streak"`
	FailureStreak           int                   `json:"failure_streak"`
	LatencyEWMA             float64               `json:"latency_ewma_ms"`
	RecentSuccessRate       float64               `json:"recent_success_rate"`
	Breakdown               SchedulerBreakdownDTO `json:"breakdown"`
	LastSuccessAt           string                `json:"last_success_at,omitempty"`
	LastFailureAt           string                `json:"last_failure_at,omitempty"`
	LastUnauthorizedAt      string                `json:"last_unauthorized_at,omitempty"`
	LastRateLimitedAt       string                `json:"last_rate_limited_at,omitempty"`
	LastTimeoutAt           string                `json:"last_timeout_at,omitempty"`
}

// SchedulerBreakdownDTO is the JSON representation of score breakdown.
type SchedulerBreakdownDTO struct {
	UnauthorizedPenalty float64 `json:"unauthorized_penalty"`
	RateLimitPenalty    float64 `json:"rate_limit_penalty"`
	TimeoutPenalty      float64 `json:"timeout_penalty"`
	ServerPenalty       float64 `json:"server_penalty"`
	FailurePenalty      float64 `json:"failure_penalty"`
	SuccessBonus        float64 `json:"success_bonus"`
	ProvenBonus         float64 `json:"proven_bonus"`
	LatencyPenalty      float64 `json:"latency_penalty"`
	SuccessRatePenalty  float64 `json:"success_rate_penalty"`
}

// SchedulerStatsResponse is the full scheduler stats response.
type SchedulerStatsResponse struct {
	Total       int                  `json:"total"`
	Healthy     int                  `json:"healthy"`
	Warm        int                  `json:"warm"`
	Risky       int                  `json:"risky"`
	Banned      int                  `json:"banned"`
	AvgScore    float64              `json:"avg_score"`
	Auths       []AuthHealthSnapshot `json:"auths"`
}

// GetSchedulerStats returns per-auth health tier, scheduler score, and breakdown.
// GET /v0/management/scheduler-stats
func (h *Handler) GetSchedulerStats(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager not available"})
		return
	}

	auths := h.authManager.List()
	resp := SchedulerStatsResponse{}
	resp.Total = len(auths)

	var scoreSum float64
	snapshots := make([]AuthHealthSnapshot, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		// Recompute on the clone to get fresh breakdown
		auth.RecomputeScheduler(1)
		snapshots = append(snapshots, buildHealthSnapshot(auth))
		switch auth.HealthTier {
		case coreauth.HealthTierHealthy:
			resp.Healthy++
		case coreauth.HealthTierWarm:
			resp.Warm++
		case coreauth.HealthTierRisky:
			resp.Risky++
		case coreauth.HealthTierBanned:
			resp.Banned++
		}
		scoreSum += auth.SchedulerScore
	}

	if resp.Total > 0 {
		resp.AvgScore = scoreSum / float64(resp.Total)
	}

	// Sort: healthy first, then by score descending
	sort.Slice(snapshots, func(i, j int) bool {
		pi := coreauth.HealthTierPriority(snapshots[i].HealthTier)
		pj := coreauth.HealthTierPriority(snapshots[j].HealthTier)
		if pi != pj {
			return pi > pj
		}
		return snapshots[i].SchedulerScore > snapshots[j].SchedulerScore
	})

	resp.Auths = snapshots
	c.JSON(http.StatusOK, resp)
}

func buildHealthSnapshot(a *coreauth.Auth) AuthHealthSnapshot {
	breakdown := a.SchedulerBreakdown()

	s := AuthHealthSnapshot{
		ID:                      a.ID,
		Provider:                a.Provider,
		HealthTier:              a.HealthTier,
		SchedulerScore:          a.SchedulerScore,
		DynamicConcurrencyLimit: a.DynamicConcurrencyLimit,
		ActiveRequests:          a.ActiveRequests,
		TotalRequests:           a.TotalRequests,
		SuccessStreak:           a.SuccessStreak,
		FailureStreak:           a.FailureStreak,
		LatencyEWMA:             a.LatencyEWMA,
		RecentSuccessRate:       a.RecentSuccessRate(),
		Breakdown: SchedulerBreakdownDTO{
			UnauthorizedPenalty: breakdown.UnauthorizedPenalty,
			RateLimitPenalty:    breakdown.RateLimitPenalty,
			TimeoutPenalty:      breakdown.TimeoutPenalty,
			ServerPenalty:       breakdown.ServerPenalty,
			FailurePenalty:      breakdown.FailurePenalty,
			SuccessBonus:        breakdown.SuccessBonus,
			ProvenBonus:         breakdown.ProvenBonus,
			LatencyPenalty:      breakdown.LatencyPenalty,
			SuccessRatePenalty:  breakdown.SuccessRatePenalty,
		},
	}
	if !a.LastSuccessAt.IsZero() {
		s.LastSuccessAt = a.LastSuccessAt.Format(time.RFC3339)
	}
	if !a.LastFailureAt.IsZero() {
		s.LastFailureAt = a.LastFailureAt.Format(time.RFC3339)
	}
	if !a.LastUnauthorizedAt.IsZero() {
		s.LastUnauthorizedAt = a.LastUnauthorizedAt.Format(time.RFC3339)
	}
	if !a.LastRateLimitedAt.IsZero() {
		s.LastRateLimitedAt = a.LastRateLimitedAt.Format(time.RFC3339)
	}
	if !a.LastTimeoutAt.IsZero() {
		s.LastTimeoutAt = a.LastTimeoutAt.Format(time.RFC3339)
	}
	return s
}
