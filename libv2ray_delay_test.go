package libv2ray

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestPrefixOutboundTags(t *testing.T) {
	content, tag, err := prefixOutboundTags(`{
		// Xray's own loader accepts comments too
		"outbounds": [
			{
				"tag": "proxy",
				"protocol": "vless",
				"streamSettings": {
					"sockopt": {"dialerProxy": "hop", "mark": 4294967295},
					"tlsSettings": {"echSockopt": {"dialerProxy": "ech"}},
					"xhttpSettings": {"extra": {"downloadSettings": {"sockopt": {"DialerProxy": "hop"}}}}
				}
			},
			{"Tag": "hop", "protocol": "freedom", "streamSettings": {"sockopt": {"dialerProxy": "elsewhere"}}},
			{"tag": "ech", "protocol": "freedom"},
			{"protocol": "blackhole"}
		]
	}`, "delay-test-1")
	if err != nil {
		t.Fatal(err)
	}
	if tag != "delay-test-1/proxy" {
		t.Error("the measurement dials through ", tag)
	}
	want := `{
		"outbounds": [
			{
				"tag": "delay-test-1/proxy",
				"protocol": "vless",
				"streamSettings": {
					"sockopt": {"dialerProxy": "delay-test-1/hop", "mark": 4294967295},
					"tlsSettings": {"echSockopt": {"dialerProxy": "delay-test-1/ech"}},
					"xhttpSettings": {"extra": {"downloadSettings": {"sockopt": {"DialerProxy": "delay-test-1/hop"}}}}
				}
			},
			{"Tag": "delay-test-1/hop", "protocol": "freedom", "streamSettings": {"sockopt": {"dialerProxy": "elsewhere"}}},
			{"tag": "delay-test-1/ech", "protocol": "freedom"},
			{"tag": "delay-test-1#3", "protocol": "blackhole"}
		]
	}`
	if got, want := decodeJSON(t, content), decodeJSON(t, want); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMeasureOutboundDelayKeepsConfigurationsApart(t *testing.T) {
	// Configurations with the same tags, measured at the same time. Each dials through a dialerProxy
	// "hop" of its own: that of the working one reaches a server that answers, that of the broken one a
	// closed port. With an instance per measurement, a dialerProxy was looked up in the instance created
	// last, so either could go through the hop of the other.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := listener.Addr().String()
	listener.Close()

	config := func(hopTarget string) string {
		return fmt.Sprintf(`{
			"log": {"loglevel": "none"},
			"outbounds": [
				{"tag": "proxy", "protocol": "freedom", "streamSettings": {"sockopt": {"dialerProxy": "hop"}}},
				{"tag": "hop", "protocol": "freedom", "settings": {"redirect": %q}}
			]
		}`, hopTarget)
	}
	working, broken := config(server.Listener.Addr().String()), config(closedAddress)
	const url = "http://delay.test/generate_204"

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := MeasureOutboundDelay(working, url); err != nil {
				t.Error("the working configuration failed: ", err)
			}
		}()
		go func() {
			defer wg.Done()
			if delay, err := MeasureOutboundDelay(broken, url); err == nil {
				t.Error("the broken configuration was measured at ", delay, " ms")
			}
		}()
	}
	wg.Wait()

	if delayInstanceRunning() {
		t.Error("the shared instance still runs after the measurements")
	}
}

func TestMeasureOutboundDelayCleansUpAfterAnError(t *testing.T) {
	// The second outbound cannot be added under the tag of the first. The first is removed again, and
	// the shared instance closes with the measurement.
	_, err := MeasureOutboundDelay(`{
		"log": {"loglevel": "none"},
		"outbounds": [
			{"tag": "proxy", "protocol": "freedom"},
			{"tag": "proxy", "protocol": "freedom"}
		]
	}`, "http://delay.test/generate_204")
	if err == nil {
		t.Error("two outbounds with one tag were measured")
	}
	if delayInstanceRunning() {
		t.Error("the shared instance still runs after the failed measurement")
	}
}

func delayInstanceRunning() bool {
	delayInstance.Lock()
	defer delayInstance.Unlock()
	return delayInstance.instance != nil || delayInstance.users != 0
}

func decodeJSON(t *testing.T, content string) any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
