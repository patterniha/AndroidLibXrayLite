package libv2ray

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	core "github.com/xtls/xray-core/core"
	corestats "github.com/xtls/xray-core/features/stats"
	coreserial "github.com/xtls/xray-core/infra/conf/serial"
)

// QueryAllOutboundTrafficStats retrieves and resets all outbound traffic counters.
// Returns a single-line text in format: tag,direction,value;tag,direction,value;
// Returns an empty string if the stats manager is not initialized or no counters exist.
func (x *CoreController) QueryAllOutboundTrafficStats() string {
	if x.statsManager == nil {
		return ""
	}

	var b strings.Builder

	x.statsManager.VisitCounters(func(name string, counter corestats.Counter) bool {
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[0] != "outbound" || parts[2] != "traffic" {
			return true
		}

		tag := parts[1]
		direct := parts[3]
		value := counter.Set(0)
		if value <= 0 {
			return true
		}

		b.WriteString(tag)
		b.WriteByte(',')
		b.WriteString(direct)
		b.WriteByte(',')
		b.WriteString(strconv.FormatInt(value, 10))
		b.WriteByte(';')
		return true
	})
	return b.String()
}

// MeasureDelay measures network latency to a specified URL through the current core instance
// Uses a 12-second timeout context and returns the round-trip time in milliseconds
// An error is returned if the connection fails or returns an unexpected status
func (x *CoreController) MeasureDelay(url string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	return measureInstDelay(ctx, x.coreInstance, "", url)
}

// MeasureOutboundDelay measures the outbound delay for a given configuration and URL, through the first
// outbound of the configuration. All measurements run in one shared instance (see libv2ray_delay.go).
func MeasureOutboundDelay(ConfigureFileContent string, url string) (int64, error) {
	prefix := delayDefaultTag + "-" + strconv.FormatUint(delayMeasurements.Add(1), 10)
	content, tag, err := prefixOutboundTags(ConfigureFileContent, prefix)
	if err != nil {
		return -1, fmt.Errorf("config load error: %w", err)
	}
	config, err := coreserial.LoadJSONConfig(strings.NewReader(content))
	if err != nil {
		return -1, fmt.Errorf("config load error: %w", err)
	}

	inst, err := acquireDelayInstance(config)
	if err != nil {
		return -1, fmt.Errorf("instance creation failed: %w", err)
	}
	defer releaseDelayInstance()

	remove, err := addDelayOutbounds(inst, config.Outbound)
	defer remove()
	if err != nil {
		return -1, fmt.Errorf("outbound creation failed: %w", err)
	}
	return measureInstDelay(context.Background(), inst, tag, url)
}

// measureInstDelay measures the delay for an instance to a given URL, through the outbound with
// outboundTag, or as the instance routes it when outboundTag is empty
func measureInstDelay(ctx context.Context, inst *core.Instance, outboundTag string, url string) (int64, error) {
	if inst == nil {
		return -1, errors.New("core instance is nil")
	}

	if url == "" {
		url = "https://www.google.com/generate_204"
	}

	tr := &http.Transport{
		TLSHandshakeTimeout: 6 * time.Second,
		DisableKeepAlives:   false,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := corenet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
			if err != nil {
				return nil, err
			}
			if outboundTag != "" {
				// A session content for each dial: the dispatcher clears the tag in the one it reads.
				ctx = session.SetForcedOutboundTagToContext(session.ContextWithContent(ctx, &session.Content{}), outboundTag)
			}
			return core.Dial(ctx, inst, dest)
		},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   12 * time.Second,
	}

	var minDuration int64 = -1
	success := false
	var lastErr error

	defer tr.CloseIdleConnections()

	const attempts = 2
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			if !success {
				return -1, ctx.Err()
			}
			return minDuration, nil
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create HTTP request: %w", err)
			continue
		}

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			lastErr = fmt.Errorf("invalid status: %s", resp.Status)
			continue
		}

		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		duration := time.Since(start).Milliseconds()
		if !success || duration < minDuration {
			minDuration = duration
		}

		success = true
	}
	if !success {
		return -1, lastErr
	}
	return minDuration, nil
}
