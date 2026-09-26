package main

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	p4configv1 "github.com/p4lang/p4runtime/go/p4/config/v1"
	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"google.golang.org/protobuf/proto"
)

func compiledPipeline(t *testing.T) *pipeline.Pipeline {
	t.Helper()
	info, err := os.ReadFile("../build/flowlet.p4info.txtpb")
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile("../build/flowlet.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := pipeline.LoadText(info, config)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfiguration(t *testing.T) {
	p := compiledPipeline(t)
	routeTable, _ := p.Table("IngressPipe.ipv4_route")
	pathTable, _ := p.Table("IngressPipe.flowlet_path")
	configTable, _ := p.Table("IngressPipe.flowlet_config")
	forward, _ := p.Action("IngressPipe.set_nhop")
	flowlet, _ := p.Action("IngressPipe.select_flowlet")
	wantPorts := [4][2]uint64{{1, 2}, {1, 2}, {1, 2}, {2, 1}}
	for device := 1; device <= 4; device++ {
		for path := 0; path < 2; path++ {
			got, err := entries(p, device, path, 250000)
			if err != nil {
				t.Fatal(err)
			}
			var routeCount, pathCount, defaults int
			for _, entry := range got {
				action := entry.GetAction().GetAction()
				if entry.IsDefaultAction {
					defaults++
					if entry.TableId == configTable.ID {
						value, err := codec.DecodeUint(action.Params[0].Value)
						if err != nil || value != 250000 {
							t.Fatalf("wrong timeout: %v, %v", value, err)
						}
					}
					continue
				}
				if entry.TableId == routeTable.ID {
					match := entry.Match[0].GetLpm()
					if match.PrefixLen != 32 || len(match.Value) != 4 || match.Value[0] != 10 ||
						match.Value[1] != 0 || match.Value[2] != []byte{1, 4}[routeCount] || match.Value[3] != 1 {
						t.Fatalf("s%d: incorrect host prefix: %v", device, match)
					}
					port := wantPorts[device-1][routeCount]
					if (device == 1 || device == 4) && port == 2 {
						if action.ActionId != flowlet.ID || !slices.Equal(action.Params[0].Value, []byte{byte(path)}) {
							t.Fatalf("s%d: incorrect flowlet route: %v", device, action)
						}
					} else {
						actualPort, _ := codec.DecodeUint(action.Params[0].Value)
						if action.ActionId != forward.ID || actualPort != port {
							t.Fatalf("s%d: incorrect static next hop: %v", device, action)
						}
					}
					routeCount++
				} else if entry.TableId == pathTable.ID {
					branch, _ := codec.DecodeUint(entry.Match[0].GetExact().Value)
					port, _ := codec.DecodeUint(action.Params[0].Value)
					peerPort := 1
					if device == 4 {
						peerPort = 2
					}
					if branch != uint64(pathCount) || port != branch+2 || action.ActionId != forward.ID ||
						!slices.Equal(action.Params[1].Value, codec.MustMAC(switchMAC(device, int(port)))) ||
						!slices.Equal(action.Params[2].Value, codec.MustMAC(switchMAC(int(port), peerPort))) {
						t.Fatalf("s%d: incorrect path member: %v", device, entry)
					}
					pathCount++
				} else {
					t.Fatalf("unexpected entry: %v", entry)
				}
			}
			wantPaths := 0
			if device == 1 || device == 4 {
				wantPaths = 2
			}
			if routeCount != 2 || pathCount != wantPaths || defaults != 3 {
				t.Fatalf("s%d: routes=%d, paths=%d, defaults=%d", device, routeCount, pathCount, defaults)
			}
		}
	}
	for _, args := range []struct {
		device, path int
		timeout      uint64
	}{
		{0, 0, 1}, {5, 0, 1}, {1, -1, 1}, {1, 2, 1}, {1, 0, 0}, {1, 0, 1 << 48},
	} {
		if _, err := entries(p, args.device, args.path, args.timeout); err == nil {
			t.Fatalf("accepted invalid settings: %v", args)
		}
	}
	if _, err := entries(p, 1, 0, (1<<48)-1); err != nil {
		t.Fatal(err)
	}
}

func TestExactReadback(t *testing.T) {
	p := compiledPipeline(t)
	want, err := entries(p, 1, 0, defaultTimeoutUS)
	if err != nil {
		t.Fatal(err)
	}
	routeTable, _ := p.Table("IngressPipe.ipv4_route")
	for _, scenario := range []string{"exact", "reordered", "padded", "missing", "extra", "wrong-port", "wrong-prefix", "wrong-mac", "wrong-default", "wrong-timeout", "wrong-path", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			got := make([]*p4v1.TableEntry, len(want))
			for i, entry := range want {
				got[i] = proto.Clone(entry).(*p4v1.TableEntry)
			}
			routeIndex := slices.IndexFunc(got, func(e *p4v1.TableEntry) bool {
				return e.TableId == routeTable.ID && !e.IsDefaultAction
			})
			route := got[routeIndex]
			switch scenario {
			case "reordered":
				slices.Reverse(got)
				slices.Reverse(route.GetAction().GetAction().Params)
			case "padded":
				route.GetAction().GetAction().Params[0].Value = []byte{1}
			case "missing":
				got = got[1:]
			case "extra":
				got = append(got, got[0])
			case "wrong-port":
				route.GetAction().GetAction().Params[0].Value = []byte{9}
			case "wrong-prefix":
				route.Match[0].GetLpm().PrefixLen = 24
			case "wrong-mac":
				route.GetAction().GetAction().Params[2].Value = []byte{9}
			case "wrong-default":
				got[len(got)-1].Action = proto.Clone(route.Action).(*p4v1.TableAction)
			case "wrong-timeout":
				got[0].GetAction().GetAction().Params[0].Value = []byte{1}
			case "wrong-path":
				got[1].Match[0].GetExact().Value = []byte{1}
			case "duplicate":
				got[2] = got[1]
			}
			err := compareEntries(want, got)
			valid := scenario == "exact" || scenario == "reordered" || scenario == "padded"
			if (err == nil) != valid {
				t.Fatalf("comparison error: %v", err)
			}
		})
	}
}

type recordingSwitch struct {
	p                    *pipeline.Pipeline
	entries              []*p4v1.TableEntry
	setCalls, writeCalls int
	readError            error
}

func (s *recordingSwitch) SetPipeline(_ context.Context, p *pipeline.Pipeline, opts client.SetPipelineOptions) (client.SetPipelineResult, error) {
	s.setCalls++
	if opts.Action != client.PipelineVerifyAndCommit || !opts.NoFallback {
		return client.SetPipelineResult{}, errors.New("unexpected pipeline operation")
	}
	s.p = p
	return client.SetPipelineResult{}, nil
}

func (s *recordingSwitch) GetPipeline(context.Context) (*pipeline.Pipeline, error) {
	return s.p, s.readError
}

func (s *recordingSwitch) WriteTableEntry(_ context.Context, kind client.UpdateType, entry *p4v1.TableEntry) error {
	s.writeCalls++
	if (entry.IsDefaultAction && kind != client.UpdateModify) || (!entry.IsDefaultAction && kind != client.UpdateInsert) {
		return errors.New("unexpected table write")
	}
	return nil
}

func (s *recordingSwitch) ReadTableEntries(context.Context, uint32) ([]*p4v1.TableEntry, error) {
	var out []*p4v1.TableEntry
	for _, entry := range s.entries {
		if !entry.IsDefaultAction {
			out = append(out, entry)
		}
	}
	return out, nil
}

func (s *recordingSwitch) Read(_ context.Context, selectors ...*p4v1.Entity) ([]*p4v1.Entity, error) {
	var out []*p4v1.Entity
	for _, entry := range s.entries {
		if entry.IsDefaultAction && entry.TableId == selectors[0].GetTableEntry().TableId {
			out = append(out, &p4v1.Entity{Entity: &p4v1.Entity_TableEntry{TableEntry: entry}})
		}
	}
	return out, nil
}

func TestConfigureAndVerifyOnly(t *testing.T) {
	p := compiledPipeline(t)
	for _, verifyOnly := range []bool{false, true} {
		want, err := entries(p, 1, 0, defaultTimeoutUS)
		if err != nil {
			t.Fatal(err)
		}
		s := &recordingSwitch{p: p, entries: want}
		if err := configure(context.Background(), s, p, 1, 0, defaultTimeoutUS, verifyOnly); err != nil {
			t.Fatal(err)
		}
		if verifyOnly && (s.setCalls != 0 || s.writeCalls != 0) {
			t.Fatal("verify-only changed configuration")
		}
		if !verifyOnly && (s.setCalls != 1 || s.writeCalls != 5) {
			t.Fatalf("unexpected writes: pipeline=%d, tables=%d", s.setCalls, s.writeCalls)
		}
		s.readError = errors.New("read failed")
		if err := configure(context.Background(), s, p, 1, 0, defaultTimeoutUS, verifyOnly); err == nil {
			t.Fatal("read failure accepted")
		}
		s.readError = nil
		s.p, err = pipeline.New(p.Info(), []byte("different pipeline"))
		if err != nil {
			t.Fatal(err)
		}
		if err := configure(context.Background(), s, p, 1, 0, defaultTimeoutUS, true); err == nil {
			t.Fatal("different pipeline accepted")
		}
		info := proto.Clone(p.Info()).(*p4configv1.P4Info)
		info.PkgInfo.Arch = "different"
		s.p, err = pipeline.New(info, p.DeviceConfig())
		if err != nil {
			t.Fatal(err)
		}
		if err := configure(context.Background(), s, p, 1, 0, defaultTimeoutUS, true); err == nil {
			t.Fatal("different P4Info accepted")
		}
	}
}
