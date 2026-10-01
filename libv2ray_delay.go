package libv2ray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	json_reader "github.com/xtls/xray-core/infra/conf/json"
	coreserial "github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy/blackhole"
)

// Xray runs at most one instance per process (core/xray.go: "At any time, there must be at most one
// Server instance running"): the instance created last sets the outbound manager and the DNS client
// that every dialerProxy and domainStrategy of the process resolves with. MeasureOutboundDelay
// therefore measures every configuration in one shared instance, which runs while any measurement
// does. A measurement adds the outbounds of its configuration under tags of its own, dials through the
// first of them and removes them again, so measurements that run at the same time never use each
// other's outbounds. The exit that OpenExit opens is part of the same instance, for the same reason.

// delayDefaultTag is the tag of the shared instance's own outbound, a blackhole that is its default
// handler, so that no measured outbound becomes the default. Measured tags start with it and a number.
const delayDefaultTag = "delay-test"

var delayInstance struct {
	sync.Mutex
	instance *core.Instance
	users    int
}

// delayMeasurements numbers the measurements for the tags of their outbounds.
var delayMeasurements atomic.Uint64

// delayBatches holds the batches of measurements that run or were cancelled. PattNG measures the configurations
// of a test as one batch, and ends it with CancelOutboundDelays when the test stops: it cannot interrupt a
// measurement, which blocks a Java thread in Go.
var delayBatches = struct {
	sync.Mutex
	batches map[string]*delayBatch
}{batches: map[string]*delayBatch{}}

type delayBatch struct {
	ctx    context.Context
	cancel context.CancelFunc
	users  int
	// cancelled is set by CancelOutboundDelays. The batch is then kept for the life of the process, so that a
	// measurement that starts later returns at once as well: its caller may have passed its last check already.
	// PattNG names the batch of each test anew and cancels it at most once.
	cancelled bool
}

// delayBatchOf returns the batch with name, which it adds when there is none. The caller holds delayBatches.
func delayBatchOf(name string) *delayBatch {
	batch := delayBatches.batches[name]
	if batch == nil {
		ctx, cancel := context.WithCancel(context.Background())
		batch = &delayBatch{ctx: ctx, cancel: cancel}
		delayBatches.batches[name] = batch
	}
	return batch
}

// acquireDelayBatch returns the context of the measurements of the batch with name. Each call must be followed
// by releaseDelayBatch.
func acquireDelayBatch(name string) context.Context {
	delayBatches.Lock()
	defer delayBatches.Unlock()

	batch := delayBatchOf(name)
	batch.users++
	return batch.ctx
}

// releaseDelayBatch forgets the batch with name once none of its measurements runs, unless it was cancelled.
func releaseDelayBatch(name string) {
	delayBatches.Lock()
	defer delayBatches.Unlock()

	batch := delayBatches.batches[name]
	batch.users--
	if batch.users == 0 && !batch.cancelled {
		batch.cancel()
		delete(delayBatches.batches, name)
	}
}

// CancelOutboundDelays ends the measurements of the batch with name at once: the running ones return -1, and so
// do those that start later. The measurements of other batches go on.
func CancelOutboundDelays(name string) {
	delayBatches.Lock()
	defer delayBatches.Unlock()

	batch := delayBatchOf(name)
	batch.cancelled = true
	batch.cancel()
}

// acquireDelayInstance returns the shared instance. When neither a measurement nor the exit uses it, it
// starts one with the apps of config that they need, and the routing of the exit. Each successful call
// must be followed by releaseDelayInstance.
func acquireDelayInstance(config *core.Config) (*core.Instance, error) {
	delayInstance.Lock()
	defer delayInstance.Unlock()

	if delayInstance.instance == nil {
		var apps []*serial.TypedMessage
		for _, app := range config.App {
			if app.Type == "xray.app.proxyman.OutboundConfig" ||
				app.Type == "xray.app.proxyman.InboundConfig" ||
				app.Type == "xray.app.dispatcher.Config" ||
				app.Type == "xray.app.log.Config" {
				apps = append(apps, app)
			}
		}
		routing, err := exitRouting()
		if err != nil {
			return nil, err
		}
		apps = append(apps, routing)
		inst, err := core.New(&core.Config{
			App: apps,
			Outbound: []*core.OutboundHandlerConfig{{
				Tag:           delayDefaultTag,
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			}},
		})
		if err != nil {
			return nil, err
		}
		if err := inst.Start(); err != nil {
			inst.Close()
			return nil, err
		}
		delayInstance.instance = inst
	}
	delayInstance.users++
	return delayInstance.instance, nil
}

// releaseDelayInstance closes the shared instance once neither a measurement nor the exit uses it.
func releaseDelayInstance() {
	delayInstance.Lock()
	defer delayInstance.Unlock()

	delayInstance.users--
	if delayInstance.users == 0 {
		delayInstance.instance.Close()
		delayInstance.instance = nil
	}
}

// addDelayOutbounds adds the outbounds of a measurement to the shared instance. The returned function
// removes and closes those it added, also after an error.
func addDelayOutbounds(inst *core.Instance, configs []*core.OutboundHandlerConfig) (func(), error) {
	outbounds := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	remove := func() {
		for _, config := range configs {
			if handler := outbounds.GetHandler(config.Tag); handler != nil {
				outbounds.RemoveHandler(context.Background(), config.Tag)
				handler.Close()
			}
		}
	}
	for _, config := range configs {
		if err := core.AddOutboundHandler(inst, config); err != nil {
			return remove, err
		}
	}
	return remove, nil
}

// The cores that PattNG runs on their own, for scans, key renewals and latency tests, dial out through
// the exit of the shared instance of their process, as the core of a session dials out through an
// inbound of the session's configuration: what comes in on the mixed inbound exitInboundTag, on the
// loopback address, leaves by the freedom outbound exitOutboundTag. The cores of a process share it.
const (
	exitInboundTag  = "secondary-socks"
	exitOutboundTag = "exit-node"
)

var delayExit struct {
	sync.Mutex
	inst   *core.Instance
	port   int
	users  int
	remove func()
}

// OpenExit returns the port of the exit, which it opens when it is not open; the shared instance runs
// while the exit is open. Each successful call must be followed by CloseExit.
func OpenExit() (int64, error) {
	delayExit.Lock()
	defer delayExit.Unlock()

	if delayExit.users > 0 {
		delayExit.users++
		return int64(delayExit.port), nil
	}
	port, err := freeLoopbackPort()
	if err != nil {
		return -1, fmt.Errorf("no port for the exit: %w", err)
	}
	config, err := coreserial.LoadJSONConfig(strings.NewReader(fmt.Sprintf(`{
		"inbounds": [{"tag": %q, "port": %d, "listen": "127.0.0.1", "protocol": "mixed", "settings": {"udp": true}}],
		"outbounds": [{"tag": %q, "protocol": "freedom"}]
	}`, exitInboundTag, port, exitOutboundTag)))
	if err != nil {
		return -1, fmt.Errorf("config load error: %w", err)
	}
	inst, err := acquireDelayInstance(config)
	if err != nil {
		return -1, fmt.Errorf("instance creation failed: %w", err)
	}
	remove, err := addDelayOutbounds(inst, config.Outbound)
	if err == nil {
		err = core.AddInboundHandler(inst, config.Inbound[0])
	}
	if err != nil {
		remove()
		releaseDelayInstance()
		return -1, fmt.Errorf("exit creation failed: %w", err)
	}
	delayExit.inst, delayExit.port, delayExit.users, delayExit.remove = inst, port, 1, remove
	return int64(port), nil
}

// CloseExit lets go of the exit that OpenExit returned. The last one closes it, and the shared instance
// with it unless a measurement runs.
func CloseExit() {
	delayExit.Lock()
	defer delayExit.Unlock()

	if delayExit.users == 0 {
		return
	}
	delayExit.users--
	if delayExit.users > 0 {
		return
	}
	inbounds := delayExit.inst.GetFeature(inbound.ManagerType()).(inbound.Manager)
	inbounds.RemoveHandler(context.Background(), exitInboundTag)
	delayExit.remove()
	delayExit.inst, delayExit.remove = nil, nil
	releaseDelayInstance()
}

// exitRouting returns the routing app of the shared instance: what comes in on the exit leaves by its
// outbound. A measurement names its outbound, which routing then has no say in.
func exitRouting() (*serial.TypedMessage, error) {
	config, err := coreserial.LoadJSONConfig(strings.NewReader(fmt.Sprintf(
		`{"routing": {"rules": [{"inboundTag": [%q], "outboundTag": %q}]}}`, exitInboundTag, exitOutboundTag)))
	if err != nil {
		return nil, err
	}
	for _, app := range config.App {
		if app.Type == "xray.app.router.Config" {
			return app, nil
		}
	}
	return nil, errors.New("the routing of the exit has no router")
}

// freeLoopbackPort returns a port of the loopback address that nothing listens on.
func freeLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// prefixOutboundTags gives every outbound of the configuration content a tag of the measurement:
// prefix followed by "/" and its own tag, or by "#" and its index when it has none. Every dialerProxy
// that names an outbound of the configuration follows it to its new tag. It returns the new content and
// the tag of the first outbound, which the measurement dials through.
func prefixOutboundTags(content string, prefix string) (string, string, error) {
	decoder := json.NewDecoder(&json_reader.Reader{Reader: strings.NewReader(content)})
	decoder.UseNumber()
	var config map[string]any
	if err := decoder.Decode(&config); err != nil {
		return "", "", err
	}
	outbounds, _ := config[jsonKey(config, "outbounds")].([]any)
	if len(outbounds) == 0 {
		return "", "", errors.New("the configuration has no outbound")
	}

	tags := make(map[string]string, len(outbounds))
	var firstTag string
	for i, element := range outbounds {
		outbound, ok := element.(map[string]any)
		if !ok {
			return "", "", fmt.Errorf("outbound %d is not an object", i)
		}
		key := jsonKey(outbound, "tag")
		newTag := prefix + "#" + strconv.Itoa(i)
		if tag, _ := outbound[key].(string); tag != "" {
			newTag = prefix + "/" + tag
			tags[tag] = newTag
		}
		outbound[key] = newTag
		if i == 0 {
			firstTag = newTag
		}
	}
	for _, element := range outbounds {
		relinkDialerProxies(element, tags)
	}

	newContent, err := json.Marshal(config)
	if err != nil {
		return "", "", err
	}
	return string(newContent), firstTag, nil
}

// relinkDialerProxies points every dialerProxy in value that names an outbound of the configuration at
// that outbound's new tag. Any other dialerProxy names no outbound of the measurement either way.
func relinkDialerProxies(value any, tags map[string]string) {
	switch value := value.(type) {
	case map[string]any:
		for key, element := range value {
			if tag, ok := element.(string); ok && strings.EqualFold(key, "dialerProxy") {
				if newTag, ok := tags[tag]; ok {
					value[key] = newTag
				}
				continue
			}
			relinkDialerProxies(element, tags)
		}
	case []any:
		for _, element := range value {
			relinkDialerProxies(element, tags)
		}
	}
}

// jsonKey returns the key of object that Xray reads as name: Go matches JSON keys to fields without
// regard to case, preferring an exact match. It returns name when object has no such key.
func jsonKey(object map[string]any, name string) string {
	if _, ok := object[name]; ok {
		return name
	}
	for key := range object {
		if strings.EqualFold(key, name) {
			return key
		}
	}
	return name
}
