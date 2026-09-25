package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
	"google.golang.org/protobuf/proto"
)

type route struct {
	destination string
	port        uint64
	sourceMAC   string
	nextMAC     string
}

func switchMAC(device, port int) string {
	return fmt.Sprintf("02:00:00:00:%02x:%02x", device, port)
}

func routes(device, path int) ([]route, error) {
	if path < 0 || path > 1 {
		return nil, fmt.Errorf("static path must be 0 or 1")
	}
	var ports [2]int
	var next [2]string
	switch device {
	case 1:
		ports = [2]int{1, 2 + path}
		next = [2]string{"00:00:00:00:01:01", switchMAC(2+path, 1)}
	case 2, 3:
		ports = [2]int{1, 2}
		next = [2]string{switchMAC(1, device), switchMAC(4, device)}
	case 4:
		ports = [2]int{2 + path, 1}
		next = [2]string{switchMAC(2+path, 2), "00:00:00:00:04:01"}
	default:
		return nil, fmt.Errorf("device must be 1..4, got %d", device)
	}
	out := make([]route, 0, 2)
	for i, destination := range []string{"10.0.1.1", "10.0.4.1"} {
		out = append(out, route{destination, uint64(ports[i]), switchMAC(device, ports[i]), next[i]})
	}
	return out, nil
}

func entries(p *pipeline.Pipeline, device, path int) ([]*p4v1.TableEntry, error) {
	routes, err := routes(device, path)
	if err != nil {
		return nil, err
	}
	var out []*p4v1.TableEntry
	for _, route := range routes {
		entry, err := tableentry.NewBuilder(p, "IngressPipe.ipv4_route").
			Match("hdr.ipv4.dst_addr", tableentry.LPM(codec.MustIPv4(route.destination), 32)).
			Action("IngressPipe.set_nhop",
				tableentry.Param("port", codec.MustEncodeUint(route.port, 9)),
				tableentry.Param("src_mac", codec.MustMAC(route.sourceMAC)),
				tableentry.Param("dst_mac", codec.MustMAC(route.nextMAC))).Build()
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	entry, err := tableentry.NewBuilder(p, "IngressPipe.ipv4_route").
		AsDefault().Action("IngressPipe.drop").Build()
	if err != nil {
		return nil, err
	}
	return append(out, entry), nil
}

// P4Runtime permits both padded and shortest-form bytestrings for unsigned fields.
func canonicalEntry(entry *p4v1.TableEntry) *p4v1.TableEntry {
	out := proto.Clone(entry).(*p4v1.TableEntry)
	trim := func(b []byte) []byte {
		for len(b) > 1 && b[0] == 0 {
			b = b[1:]
		}
		return b
	}
	for _, match := range out.Match {
		if lpm := match.GetLpm(); lpm != nil {
			lpm.Value = trim(lpm.Value)
		}
	}
	slices.SortFunc(out.Match, func(a, b *p4v1.FieldMatch) int {
		return int(a.FieldId) - int(b.FieldId)
	})
	if action := out.GetAction().GetAction(); action != nil {
		for _, param := range action.Params {
			param.Value = trim(param.Value)
		}
		slices.SortFunc(action.Params, func(a, b *p4v1.Action_Param) int {
			return int(a.ParamId) - int(b.ParamId)
		})
	}
	return out
}

func compareEntries(want, got []*p4v1.TableEntry) error {
	if len(want) != len(got) {
		return fmt.Errorf("entry count: want %d, got %d", len(want), len(got))
	}
	remaining := append([]*p4v1.TableEntry(nil), got...)
	for _, entry := range want {
		index := slices.IndexFunc(remaining, func(actual *p4v1.TableEntry) bool {
			return proto.Equal(canonicalEntry(entry), canonicalEntry(actual))
		})
		if index < 0 {
			return fmt.Errorf("readback differs: missing expected entry %v", entry)
		}
		remaining = slices.Delete(remaining, index, index+1)
	}
	return nil
}

type switchAPI interface {
	SetPipeline(context.Context, *pipeline.Pipeline, client.SetPipelineOptions) (client.SetPipelineResult, error)
	GetPipeline(context.Context) (*pipeline.Pipeline, error)
	WriteTableEntry(context.Context, client.UpdateType, *p4v1.TableEntry) error
	ReadTableEntries(context.Context, uint32) ([]*p4v1.TableEntry, error)
	Read(context.Context, ...*p4v1.Entity) ([]*p4v1.Entity, error)
}

func configure(ctx context.Context, c switchAPI, p *pipeline.Pipeline, device, path int, verifyOnly bool) error {
	want, err := entries(p, device, path)
	if err != nil {
		return err
	}
	if !verifyOnly {
		_, err = c.SetPipeline(ctx, p, client.SetPipelineOptions{
			Action: client.PipelineVerifyAndCommit, NoFallback: true,
		})
		if err != nil {
			return err
		}
		for _, entry := range want {
			if !entry.IsDefaultAction {
				if err := c.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
					return err
				}
			}
		}
	}
	actualPipeline, err := c.GetPipeline(ctx)
	if err != nil {
		return err
	}
	if actualPipeline == nil || !proto.Equal(p.Info(), actualPipeline.Info()) ||
		!bytes.Equal(p.DeviceConfig(), actualPipeline.DeviceConfig()) {
		return fmt.Errorf("pipeline readback differs")
	}
	got, err := c.ReadTableEntries(ctx, 0)
	if err != nil {
		return err
	}
	for _, expected := range want {
		if !expected.IsDefaultAction {
			continue
		}
		entities, err := c.Read(ctx, &p4v1.Entity{Entity: &p4v1.Entity_TableEntry{
			TableEntry: &p4v1.TableEntry{TableId: expected.TableId, IsDefaultAction: true},
		}})
		if err != nil {
			return err
		}
		for _, entity := range entities {
			if entity.GetTableEntry() == nil {
				return fmt.Errorf("unexpected readback entity: %v", entity)
			}
			got = append(got, entity.GetTableEntry())
		}
	}
	return compareEntries(want, got)
}

func run() error {
	device := flag.Int("device", 0, "diamond switch ID (1..4)")
	path := flag.Int("static-path", 0, "static branch: 0=upper, 1=lower")
	address := flag.String("address", "", "P4Runtime address (default 127.0.0.1:50050+device)")
	infoPath := flag.String("p4info", "build/flowlet.p4info.txtpb", "P4Info text file")
	jsonPath := flag.String("pipeline", "build/flowlet.json", "BMv2 pipeline JSON")
	verifyOnly := flag.Bool("verify-only", false, "verify configuration without pipeline or table writes")
	flag.Parse()
	if _, err := routes(*device, *path); err != nil {
		return err
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *address == "" {
		*address = fmt.Sprintf("127.0.0.1:%d", 50050+*device)
	}
	info, err := os.ReadFile(*infoPath)
	if err != nil {
		return err
	}
	config, err := os.ReadFile(*jsonPath)
	if err != nil {
		return err
	}
	p, err := pipeline.LoadText(info, config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, *address, client.WithDeviceID(uint64(*device)),
		client.WithElectionID(client.ElectionID{Low: 1}),
		client.WithLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))))
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.BecomePrimary(ctx); err != nil {
		return err
	}
	if err := configure(ctx, c, p, *device, *path, *verifyOnly); err != nil {
		return fmt.Errorf("s%d: %w", *device, err)
	}
	fmt.Printf("s%d: pipeline and routes verified\n", *device)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
