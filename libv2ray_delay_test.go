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

func TestMeasureOutboundDelayQueriesECHThroughOwnOutbound(t *testing.T) {
	// Configurations with an ECH outbound under one tag, as PattNG appends it, measured at the same
	// time. The ECH config query of each goes through the ECH outbound of its own configuration, which
	// sends it to the DNS server of that configuration. No VLESS server answers, so every measurement
	// fails after its query.
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	config := func(name string, dnsServer string) string {
		return fmt.Sprintf(`{
			"log": {"loglevel": "none"},
			"outbounds": [
				{
					"tag": "proxy",
					"protocol": "vless",
					"settings": {"address": "127.0.0.1", "port": %d, "id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"},
					"streamSettings": {
						"security": "tls",
						"tlsSettings": {
							"serverName": "%s.example",
							"echConfigList": "%s.example+udp://127.0.0.1:9",
							"echSockopt": {"dialerProxy": "ech-out"}
						}
					}
				},
				{"tag": "ech-out", "protocol": "freedom", "settings": {"redirect": %q}}
			]
		}`, server.Addr().(*net.TCPAddr).Port, name, name, dnsServer)
	}
	var queriesA, queriesB dnsQueries
	configA, configB := config("a", startDNSServer(t, &queriesA)), config("b", startDNSServer(t, &queriesB))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			MeasureOutboundDelay(configA, "http://delay.test/generate_204")
		}()
		go func() {
			defer wg.Done()
			MeasureOutboundDelay(configB, "http://delay.test/generate_204")
		}()
	}
	wg.Wait()

	for _, c := range []struct {
		name    string
		queries *dnsQueries
	}{{"a.example", &queriesA}, {"b.example", &queriesB}} {
		names := c.queries.get()
		if len(names) == 0 {
			t.Error("the ECH outbound for ", c.name, " sent no query")
		}
		for _, name := range names {
			if name != c.name {
				t.Error("the ECH outbound for ", c.name, " sent the query for ", name)
			}
		}
	}
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

// dnsQueries records the names that a DNS server of a test was asked for.
type dnsQueries struct {
	sync.Mutex
	names []string
}

func (q *dnsQueries) add(name string) {
	q.Lock()
	defer q.Unlock()
	q.names = append(q.names, name)
}

func (q *dnsQueries) get() []string {
	q.Lock()
	defer q.Unlock()
	return append([]string(nil), q.names...)
}

// startDNSServer starts a UDP DNS server that records the name of each query in queries and answers
// NXDOMAIN, and returns its address.
func startDNSServer(t *testing.T, queries *dnsQueries) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			name, ok := dnsQuestionName(buffer[:n])
			if !ok {
				continue
			}
			queries.add(name)
			response := append([]byte(nil), buffer[:n]...)
			response[2] |= 0x80                   // QR: a response
			response[3] = response[3]&0xf0 | 0x03 // RCODE: NXDOMAIN
			conn.WriteTo(response, addr)
		}
	}()
	return conn.LocalAddr().String()
}

// dnsQuestionName returns the name in the question of a DNS message.
func dnsQuestionName(message []byte) (string, bool) {
	var labels []string
	for offset := 12; offset < len(message); {
		length := int(message[offset])
		if length == 0 {
			return strings.Join(labels, "."), true
		}
		offset++
		if offset+length > len(message) {
			return "", false
		}
		labels = append(labels, string(message[offset:offset+length]))
		offset += length
	}
	return "", false
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
