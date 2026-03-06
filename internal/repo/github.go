package repo

import (
	"errors"
	"log"
	"time"

	"github.com/google/go-github/v59/github"
)

const maxRetries = 5

// waitForRateLimit inspects err and, if it is a GitHub rate limit error, sleeps
// for the appropriate duration and returns true. Returns false for any other error.
func waitForRateLimit(err error, attempt int) bool {
	var rateLimitErr *github.RateLimitError
	var abuseErr *github.AbuseRateLimitError

	if errors.As(err, &rateLimitErr) {
		waitDuration := time.Until(rateLimitErr.Rate.Reset.Time.Add(time.Second))
		log.Printf("GitHub rate limit exceeded (attempt %d/%d). Waiting %s until reset...", attempt+1, maxRetries, waitDuration.Round(time.Second))
		time.Sleep(waitDuration)
		return true
	} else if errors.As(err, &abuseErr) {
		retryAfter := abuseErr.GetRetryAfter()
		log.Printf("GitHub secondary rate limit (abuse) exceeded (attempt %d/%d). Waiting %s...", attempt+1, maxRetries, retryAfter.Round(time.Second))
		time.Sleep(retryAfter)
		return true
	}

	return false
}

// ghDo calls fn, retrying on GitHub rate limit errors. It handles both primary
// rate limits (RateLimitError) and secondary/abuse rate limits (AbuseRateLimitError).
func ghDo[T any](fn func() (T, *github.Response, error)) (T, *github.Response, error) {
	for attempt := range maxRetries {
		result, resp, err := fn()
		if err == nil || !waitForRateLimit(err, attempt) {
			return result, resp, err
		}
	}

	// All retries were rate-limited; make one final attempt and return whatever happens.
	return fn()
}

// ghDoNoBody is like ghDo but for GitHub API calls that return only (*Response, error),
// such as Teams.AddTeamRepoBySlug.
func ghDoNoBody(fn func() (*github.Response, error)) (*github.Response, error) {
	for attempt := range maxRetries {
		resp, err := fn()
		if err == nil || !waitForRateLimit(err, attempt) {
			return resp, err
		}
	}

	// All retries were rate-limited; make one final attempt and return whatever happens.
	return fn()
}
