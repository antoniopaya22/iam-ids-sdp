package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antoniopaya22/iam-ids-sdp/internal/api"
)

// Get performs one request on an established session against one AH (round robin by
// index) and returns the HTTP status. withToken=false omits the bearer token, which the
// AH must refuse in proposed mode.
func (c *Client) Get(ctx context.Context, s *SessionFile, path string, withToken bool, index int) (int, error) {
	g := s.Session.Grants[index%len(s.Session.Grants)]
	token := ""
	if withToken {
		token = s.Token
	}
	return c.get(ctx, &Counter{}, g, path, token)
}

// LoadOptions configure a closed-loop synthetic workload: each worker sends a request,
// waits for the answer, sleeps Think, and repeats, spreading requests over every AH of
// the session.
type LoadOptions struct {
	Duration time.Duration
	Think    time.Duration
	Workers  int
	Path     string
}

// LoadResult summarises a workload run.
type LoadResult struct {
	OK              int64   `json:"ok"`
	Failed          int64   `json:"failed"`
	Seconds         float64 `json:"seconds"`
	RequestsPerSec  float64 `json:"requests_per_sec"`
	RequestsPer10m  float64 `json:"requests_per_10min"`
	MeanLatencyMs   float64 `json:"mean_latency_ms"`
	P95LatencyMs    float64 `json:"p95_latency_ms"`
	BytesTransfered int64   `json:"bytes"`
}

// Load runs the workload on an established session.
func (c *Client) Load(ctx context.Context, s *SessionFile, o LoadOptions) LoadResult {
	if o.Workers <= 0 {
		o.Workers = 1
	}
	if o.Path == "" {
		o.Path = s.Session.Path
	}
	counter := &Counter{}
	hc := c.GatewayClient(counter, true, 10*time.Second)
	ctx, cancel := context.WithTimeout(ctx, o.Duration)
	defer cancel()
	var ok, failed, next atomic.Int64
	var mu sync.Mutex
	var lat []float64
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < o.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				g := s.Session.Grants[int(next.Add(1)-1)%len(s.Session.Grants)]
				t0 := time.Now()
				status, err := doGet(ctx, hc, g, o.Path, s.Token)
				if ctx.Err() != nil {
					return // the request was cut by the end of the run: not counted
				}
				if err == nil && status/100 == 2 {
					ok.Add(1)
					mu.Lock()
					lat = append(lat, float64(time.Since(t0).Microseconds())/1000)
					mu.Unlock()
				} else {
					failed.Add(1)
				}
				if o.Think > 0 {
					select {
					case <-ctx.Done():
					case <-time.After(o.Think):
					}
				}
			}
		}()
	}
	wg.Wait()
	secs := time.Since(start).Seconds()
	r := LoadResult{OK: ok.Load(), Failed: failed.Load(), Seconds: secs, BytesTransfered: counter.Total()}
	if secs > 0 {
		r.RequestsPerSec = float64(r.OK) / secs
		r.RequestsPer10m = r.RequestsPerSec * 600
	}
	if len(lat) > 0 {
		sort.Float64s(lat)
		var sum float64
		for _, x := range lat {
			sum += x
		}
		r.MeanLatencyMs = sum / float64(len(lat))
		r.P95LatencyMs = lat[int(float64(len(lat)-1)*0.95)]
	}
	return r
}

func doGet(ctx context.Context, hc *http.Client, g api.GatewayGrant, path, token string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s:%d%s", g.Address, g.ServicePort, path), nil)
	if err != nil {
		return 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// Proxy returns a local HTTP forwarder for an established session: ordinary programs
// (curl, a browser, a load-testing tool) talk plain HTTP to it on the IH's loopback and
// it forwards each request over mutual TLS to the AHs of the session, adding the bearer
// token in proposed mode.
func (c *Client) Proxy(s *SessionFile) http.Handler {
	hc := c.GatewayClient(&Counter{}, true, 30*time.Second)
	var next atomic.Int64
	return &httputil.ReverseProxy{
		Transport: hc.Transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			g := s.Session.Grants[int(next.Add(1)-1)%len(s.Session.Grants)]
			pr.SetURL(&url.URL{Scheme: "https", Host: fmt.Sprintf("%s:%d", g.Address, g.ServicePort)})
			pr.Out.Host = ""
			pr.Out.Header.Del("Authorization")
			if s.Token != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+s.Token)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "sdp session unavailable: "+err.Error(), http.StatusBadGateway)
		},
	}
}
