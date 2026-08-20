package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"google.golang.org/protobuf/proto"
)

type switchSession struct {
	plan   switchPlan
	client *client.Client
}

func main() {
	flags := flag.NewFlagSet("mpls-controller", flag.ExitOnError)
	p4infoPath := flags.String("p4info", "build/mpls.p4info.txtpb", "P4Info text protobuf")
	deviceConfigPath := flags.String("device-config", "build/mpls.json", "BMv2 device configuration")
	electionID := flags.Uint64("election-id", 1, "P4Runtime election ID")
	timeout := flags.Duration("timeout", 30*time.Second, "configuration deadline")
	verifyOnly := flags.Bool("verify-only", false, "verify the installed pipeline and entries without changing them")
	flags.Parse(os.Args[1:])
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "timeout must be positive")
		os.Exit(2)
	}
	if *electionID == 0 {
		fmt.Fprintln(os.Stderr, "election ID must be nonzero")
		os.Exit(2)
	}

	p, err := loadPipeline(*p4infoPath, *deviceConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load pipeline: %v\n", err)
		os.Exit(1)
	}

	signalContext, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGHUP,
		syscall.SIGTERM,
	)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, *timeout)
	defer cancel()

	if err := programSwitches(ctx, p, os.Stdout, *electionID, *verifyOnly); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadPipeline(p4infoPath, deviceConfigPath string) (*pipeline.Pipeline, error) {
	p4info, err := os.ReadFile(p4infoPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p4infoPath, err)
	}
	deviceConfig, err := os.ReadFile(deviceConfigPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", deviceConfigPath, err)
	}
	p, err := pipeline.LoadText(p4info, deviceConfig)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func programSwitches(
	ctx context.Context,
	p *pipeline.Pipeline,
	output io.Writer,
	electionID uint64,
	verifyOnly bool,
) (err error) {
	sessions, err := connectSwitches(ctx, electionID)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, closeSessions(sessions))
	}()

	for _, session := range sessions {
		if verifyOnly {
			err = verifySwitch(ctx, p, session, output)
		} else {
			err = configureSwitch(ctx, p, session, output)
		}
		if err != nil {
			return err
		}
	}
	verb := "configured"
	if verifyOnly {
		verb = "verified"
	}
	fmt.Fprintf(output, "%s %d switches\n", verb, len(sessions))
	return nil
}

func connectSwitches(ctx context.Context, electionID uint64) ([]switchSession, error) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sessions := make([]switchSession, 0, len(switchPlans))
	for _, plan := range switchPlans {
		c, err := client.Dial(
			ctx,
			plan.address,
			client.WithDeviceID(plan.deviceID),
			client.WithElectionID(client.ElectionID{Low: electionID}),
			client.WithInsecure(),
			client.WithArbitrationTimeout(5*time.Second),
			client.WithLogger(logger),
		)
		if err != nil {
			closeErr := closeSessions(sessions)
			return nil, errors.Join(fmt.Errorf("%s: connect: %w", plan.name, err), closeErr)
		}
		if err := c.BecomePrimary(ctx); err != nil {
			var currentCloseErr error
			if closeErr := c.Close(); closeErr != nil {
				currentCloseErr = fmt.Errorf("%s: close: %w", plan.name, closeErr)
			}
			closeErr := closeSessions(sessions)
			return nil, errors.Join(
				fmt.Errorf("%s: arbitration: %w", plan.name, err),
				currentCloseErr,
				closeErr,
			)
		}
		sessions = append(sessions, switchSession{plan: plan, client: c})
	}
	return sessions, nil
}

func closeSessions(sessions []switchSession) error {
	var failures []error
	for index := len(sessions) - 1; index >= 0; index-- {
		if err := sessions[index].client.Close(); err != nil {
			failures = append(failures, fmt.Errorf("%s: close: %w", sessions[index].plan.name, err))
		}
	}
	return errors.Join(failures...)
}

func configureSwitch(
	ctx context.Context,
	p *pipeline.Pipeline,
	session switchSession,
	output io.Writer,
) error {
	plan := session.plan
	if _, err := session.client.SetPipeline(ctx, p, client.SetPipelineOptions{
		Action:     client.PipelineVerifyAndCommit,
		NoFallback: true,
	}); err != nil {
		return fmt.Errorf("%s: install pipeline: %w", plan.name, err)
	}
	entries, err := buildEntries(p, plan)
	if err != nil {
		return fmt.Errorf("%s: build entries: %w", plan.name, err)
	}
	for index, entry := range entries {
		if err := session.client.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
			return fmt.Errorf(
				"%s: install %s: %w",
				plan.name,
				describeEntry(plan.entries[index]),
				err,
			)
		}
	}
	return verifyExpectedState(ctx, p, session, entries, output)
}

func verifySwitch(
	ctx context.Context,
	p *pipeline.Pipeline,
	session switchSession,
	output io.Writer,
) error {
	entries, err := buildEntries(p, session.plan)
	if err != nil {
		return fmt.Errorf("%s: build entries: %w", session.plan.name, err)
	}
	return verifyExpectedState(ctx, p, session, entries, output)
}

func verifyExpectedState(
	ctx context.Context,
	p *pipeline.Pipeline,
	session switchSession,
	entries []*p4v1.TableEntry,
	output io.Writer,
) error {
	if err := verifyPipeline(ctx, session.client, p); err != nil {
		return fmt.Errorf("%s: verify pipeline: %w", session.plan.name, err)
	}
	if err := verifyEntries(ctx, session.client, entries); err != nil {
		return fmt.Errorf("%s: verify entries: %w", session.plan.name, err)
	}
	fmt.Fprintf(output, "%s: pipeline and %d entries verified\n", session.plan.name, len(entries))
	return nil
}

func verifyPipeline(ctx context.Context, c *client.Client, expected *pipeline.Pipeline) error {
	actual, err := c.GetPipeline(ctx)
	if err != nil {
		return err
	}
	if !proto.Equal(actual.Info(), expected.Info()) {
		return errors.New("P4Info readback differs from requested pipeline")
	}
	if !bytes.Equal(actual.DeviceConfig(), expected.DeviceConfig()) {
		return errors.New("device configuration readback differs from requested pipeline")
	}
	return nil
}

func verifyEntries(ctx context.Context, c *client.Client, expected []*p4v1.TableEntry) error {
	readback, err := c.ReadTableEntries(ctx, 0)
	if err != nil {
		return err
	}
	actual := make([]*p4v1.TableEntry, 0, len(readback))
	for _, entry := range readback {
		if !entry.GetIsDefaultAction() {
			actual = append(actual, entry)
		}
	}
	if len(actual) != len(expected) {
		return fmt.Errorf("expected %d non-default entries, read back %d", len(expected), len(actual))
	}

	used := make([]bool, len(actual))
	for _, wanted := range expected {
		found := false
		for index, got := range actual {
			if !used[index] && entriesEqual(wanted, got) {
				used[index] = true
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("required table entry %d was not read back", wanted.GetTableId())
		}
	}
	return nil
}

func entriesEqual(left, right *p4v1.TableEntry) bool {
	return proto.Equal(comparableEntry(left), comparableEntry(right))
}

func comparableEntry(entry *p4v1.TableEntry) *p4v1.TableEntry {
	matches := make([]*p4v1.FieldMatch, len(entry.GetMatch()))
	for index, match := range entry.GetMatch() {
		matches[index] = proto.Clone(match).(*p4v1.FieldMatch)
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].GetFieldId() < matches[j].GetFieldId()
	})

	var action *p4v1.TableAction
	if entry.GetAction() != nil {
		action = proto.Clone(entry.GetAction()).(*p4v1.TableAction)
		if direct := action.GetAction(); direct != nil {
			sort.Slice(direct.Params, func(i, j int) bool {
				return direct.Params[i].GetParamId() < direct.Params[j].GetParamId()
			})
		}
	}

	return &p4v1.TableEntry{
		TableId:         entry.GetTableId(),
		Match:           matches,
		Action:          action,
		Priority:        entry.GetPriority(),
		IsDefaultAction: entry.GetIsDefaultAction(),
	}
}
