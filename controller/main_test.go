package main

import (
	"context"
	"errors"
	"os"
	"testing"

	p4configv1 "github.com/p4lang/p4runtime/go/p4/config/v1"
	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/client"
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

func TestRoutes(t *testing.T) {
	p := compiledPipeline(t)
	wantPorts := [4][2]byte{{1, 2}, {1, 2}, {1, 2}, {2, 1}}
	wantNext := [4][2]string{
		{"00:00:00:00:01:01", "02:00:00:00:02:01"},
		{"02:00:00:00:01:02", "02:00:00:00:04:02"},
		{"02:00:00:00:01:03", "02:00:00:00:04:03"},
		{"02:00:00:00:02:02", "00:00:00:00:04:01"},
	}
	for device := 1; device <= 4; device++ {
		r, err := routes(device, 0)
		if err != nil {
			t.Fatal(err)
		}
		got, err := entries(p, device, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 || !got[2].IsDefaultAction {
			t.Fatalf("s%d: expected two routes and default drop", device)
		}
		for i := 0; i < 2; i++ {
			entry := canonicalEntry(got[i])
			match := entry.Match[0].GetLpm()
			if match.PrefixLen != 32 || len(match.Value) != 4 || match.Value[0] != 10 ||
				match.Value[1] != 0 || match.Value[2] != []byte{1, 4}[i] || match.Value[3] != 1 {
				t.Fatalf("s%d: incorrect host prefix: %v", device, match)
			}
			port := entry.GetAction().GetAction().Params[0].Value
			if len(port) != 1 || port[0] != wantPorts[device-1][i] {
				t.Fatalf("s%d: incorrect egress port %v", device, port)
			}
			if r[i].nextMAC != wantNext[device-1][i] {
				t.Fatalf("s%d: incorrect neighbor MAC %s", device, r[i].nextMAC)
			}
		}
	}
	for _, device := range []int{-1, 0, 5} {
		if _, err := entries(p, device, 0); err == nil {
			t.Fatalf("accepted device %d", device)
		}
	}
	for _, device := range []int{1, 4} {
		lower, err := entries(p, device, 1)
		if err != nil {
			t.Fatal(err)
		}
		index := 1
		if device == 4 {
			index = 0
		}
		port := canonicalEntry(lower[index]).GetAction().GetAction().Params[0].Value
		if len(port) != 1 || port[0] != 3 {
			t.Fatalf("s%d: lower path must use port 3", device)
		}
	}
	if _, err := entries(p, 1, 2); err == nil {
		t.Fatal("accepted invalid path")
	}
}

func TestExactReadback(t *testing.T) {
	want, err := entries(compiledPipeline(t), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"exact", "reordered", "padded", "missing", "extra", "wrong-port", "wrong-prefix", "wrong-mac", "wrong-default", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			got := make([]*p4v1.TableEntry, len(want))
			for i, entry := range want {
				got[i] = proto.Clone(entry).(*p4v1.TableEntry)
			}
			switch scenario {
			case "reordered":
				got[0], got[2] = got[2], got[0]
				params := got[2].GetAction().GetAction().Params
				params[0], params[2] = params[2], params[0]
			case "padded":
				param := got[0].GetAction().GetAction().Params[0]
				param.Value = []byte{1}
			case "missing":
				got = got[:2]
			case "extra":
				got = append(got, got[0])
			case "wrong-port":
				got[0].GetAction().GetAction().Params[0].Value = []byte{9}
			case "wrong-prefix":
				got[0].Match[0].GetLpm().PrefixLen = 24
			case "wrong-mac":
				got[0].GetAction().GetAction().Params[2].Value = []byte{9}
			case "wrong-default":
				got[2].Action = proto.Clone(got[0].Action).(*p4v1.TableAction)
			case "duplicate":
				got[1] = got[0]
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
	p          *pipeline.Pipeline
	entries    []*p4v1.TableEntry
	setCalls   int
	writeCalls int
	readError  error
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
	if kind != client.UpdateInsert || entry.IsDefaultAction {
		return errors.New("unexpected route write")
	}
	return nil
}

func (s *recordingSwitch) ReadTableEntries(context.Context, uint32) ([]*p4v1.TableEntry, error) {
	return s.entries[:len(s.entries)-1], nil
}

func (s *recordingSwitch) Read(context.Context, ...*p4v1.Entity) ([]*p4v1.Entity, error) {
	return []*p4v1.Entity{{Entity: &p4v1.Entity_TableEntry{TableEntry: s.entries[len(s.entries)-1]}}}, nil
}

func TestConfigureAndVerifyOnly(t *testing.T) {
	p := compiledPipeline(t)
	for _, verifyOnly := range []bool{false, true} {
		want, err := entries(p, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		s := &recordingSwitch{p: p, entries: want}
		if err := configure(context.Background(), s, p, 1, 0, verifyOnly); err != nil {
			t.Fatal(err)
		}
		if verifyOnly && (s.setCalls != 0 || s.writeCalls != 0) {
			t.Fatal("verify-only changed configuration")
		}
		if !verifyOnly && (s.setCalls != 1 || s.writeCalls != 2) {
			t.Fatalf("unexpected writes: pipeline=%d, routes=%d", s.setCalls, s.writeCalls)
		}
		s.readError = errors.New("read failed")
		if err := configure(context.Background(), s, p, 1, 0, verifyOnly); err == nil {
			t.Fatal("read failure accepted")
		}
		s.readError = nil
		s.p, err = pipeline.New(p.Info(), []byte("different pipeline"))
		if err != nil {
			t.Fatal(err)
		}
		if err := configure(context.Background(), s, p, 1, 0, true); err == nil {
			t.Fatal("different pipeline accepted")
		}
		info := proto.Clone(p.Info()).(*p4configv1.P4Info)
		info.PkgInfo.Arch = "different"
		s.p, err = pipeline.New(info, p.DeviceConfig())
		if err != nil {
			t.Fatal(err)
		}
		if err := configure(context.Background(), s, p, 1, 0, true); err == nil {
			t.Fatal("different P4Info accepted")
		}
	}
}
