package gateway

import (
	"math"
	"time"
)

// FeatureNames is the ordered feature set "sdp-window-v1" exported to the IDS.
// Keep in sync with ids/sdp_ids/features.py.
var FeatureNames = []string{
	"req_rate",        // requests per second
	"bytes_in_rate",   // request bytes per second (headers + body, approximate)
	"bytes_out_rate",  // response body bytes per second
	"err_ratio",       // share of responses with status >= 400
	"mean_latency_ms", // mean time to serve a request at the AH
	"new_conn_rate",   // TCP/TLS connections opened per second
	"open_conns",      // connections open at the end of the window
	"stalled_conns",   // open connections with no complete request after the stall threshold
	"mean_iat_ms",     // mean inter-arrival time between requests
	"iat_cv",          // coefficient of variation of inter-arrival times
	"distinct_paths",  // number of distinct URL paths requested
}

type windowStats struct {
	requests   int
	bytesIn    int64
	bytesOut   int64
	errors     int
	latencySum time.Duration
	newConns   int
	paths      map[string]struct{}
	last       time.Time
	iats       []float64 // ms
}

func newWindowStats() *windowStats { return &windowStats{paths: map[string]struct{}{}} }

func (w *windowStats) request(at time.Time, path string, in, out int64, status int, dur time.Duration) {
	w.requests++
	w.bytesIn += in
	w.bytesOut += out
	if status >= 400 {
		w.errors++
	}
	w.latencySum += dur
	if len(w.paths) < 1000 {
		w.paths[path] = struct{}{}
	}
	if !w.last.IsZero() && len(w.iats) < 100000 {
		w.iats = append(w.iats, float64(at.Sub(w.last))/float64(time.Millisecond))
	}
	w.last = at
}

func (w *windowStats) features(secs float64, open, stalled int) map[string]float64 {
	f := map[string]float64{
		"req_rate":        float64(w.requests) / secs,
		"bytes_in_rate":   float64(w.bytesIn) / secs,
		"bytes_out_rate":  float64(w.bytesOut) / secs,
		"err_ratio":       0,
		"mean_latency_ms": 0,
		"new_conn_rate":   float64(w.newConns) / secs,
		"open_conns":      float64(open),
		"stalled_conns":   float64(stalled),
		"mean_iat_ms":     secs * 1000, // no inter-arrival observed: the whole window
		"iat_cv":          0,
		"distinct_paths":  float64(len(w.paths)),
	}
	if w.requests > 0 {
		f["err_ratio"] = float64(w.errors) / float64(w.requests)
		f["mean_latency_ms"] = float64(w.latencySum) / float64(time.Millisecond) / float64(w.requests)
	}
	if n := len(w.iats); n > 0 {
		var sum float64
		for _, x := range w.iats {
			sum += x
		}
		mean := sum / float64(n)
		var ss float64
		for _, x := range w.iats {
			ss += (x - mean) * (x - mean)
		}
		f["mean_iat_ms"] = mean
		if mean > 0 {
			f["iat_cv"] = math.Sqrt(ss/float64(n)) / mean
		}
	}
	return f
}
