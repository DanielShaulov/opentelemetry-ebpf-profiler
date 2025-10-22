// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// A command-line tool to parse interpreter data from given ELF files.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"time"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer/types"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// mock of EbpfHandler, saves some data on updates
type ebpfMock struct {
	Data          string `json:"data"`          // base64-encoded binary data
	EbpfProgIndex uint16 `json:"ebpfProgIndex"` // eBPF program index from UpdateInterpreterOffsets/UpdatePidInterpreterMapping (0 = unset)
}

func (e *ebpfMock) CollectMetrics() []metrics.Metric {
	return nil
}

func (e *ebpfMock) DeleteExeIDToStackDeltas(fileID host.FileID, mapID uint16) error {
	return nil
}

func (e *ebpfMock) DeletePidInterpreterMapping(pid libpf.PID, prefix lpm.Prefix) error {
	return nil
}

func (e *ebpfMock) DeletePidPageMappingInfo(pid libpf.PID, prefixes []lpm.Prefix) (int, error) {
	return 0, nil
}

func (e *ebpfMock) DeleteProcData(typ libpf.InterpreterType, pid libpf.PID) error {
	return nil
}

func (e *ebpfMock) DeleteStackDeltaPage(fileID host.FileID, page uint64) error {
	return nil
}

func (e *ebpfMock) RemoveReportedPID(pid libpf.PID) {
}

func (e *ebpfMock) SupportsGenericBatchOperations() bool {
	return false
}

func (e *ebpfMock) SupportsLPMTrieBatchOperations() bool {
	return false
}

func (e *ebpfMock) UpdateExeIDToStackDeltas(fileID host.FileID, deltas []ebpfapi.StackDeltaEBPF) (uint16, error) {
	return 0, nil
}

func (e *ebpfMock) UpdateInterpreterOffsets(ebpfProgIndex uint16, fileID host.FileID, offsetRanges []util.Range) error {
	if e.EbpfProgIndex != 0 && e.EbpfProgIndex != ebpfProgIndex {
		return fmt.Errorf("EbpfProgIndex mismatch: UpdatePidInterpreterMapping set %d, UpdateInterpreterOffsets set %d", e.EbpfProgIndex, ebpfProgIndex)
	}
	e.EbpfProgIndex = ebpfProgIndex
	return nil
}

func (e *ebpfMock) UpdatePidInterpreterMapping(pid libpf.PID, prefix lpm.Prefix, interpreterType uint8, fileID host.FileID, offset uint64) error {
	ebpfProgIndex := uint16(interpreterType)
	if e.EbpfProgIndex != 0 && e.EbpfProgIndex != ebpfProgIndex {
		return fmt.Errorf("EbpfProgIndex mismatch: UpdateInterpreterOffsets set %d, UpdatePidInterpreterMapping set %d", e.EbpfProgIndex, ebpfProgIndex)
	}
	e.EbpfProgIndex = ebpfProgIndex
	return nil
}

func (e *ebpfMock) UpdatePidPageMappingInfo(pid libpf.PID, prefix lpm.Prefix, fileID uint64, bias uint64) error {
	return nil
}

func (e *ebpfMock) UpdateProcData(typ libpf.InterpreterType, pid libpf.PID, data unsafe.Pointer) error {
	// Get the size of the struct based on InterpreterType
	var size uintptr
	switch typ {
	case libpf.Python:
		size = unsafe.Sizeof(support.PyProcInfo{})
	case libpf.Perl:
		size = unsafe.Sizeof(support.PerlProcInfo{})
	case libpf.PHP:
		size = unsafe.Sizeof(support.PHPProcInfo{})
	case libpf.HotSpot:
		size = unsafe.Sizeof(support.HotspotProcInfo{})
	case libpf.Ruby:
		size = unsafe.Sizeof(support.RubyProcInfo{})
	case libpf.V8:
		size = unsafe.Sizeof(support.V8ProcInfo{})
	case libpf.Dotnet:
		size = unsafe.Sizeof(support.DotnetProcInfo{})
	case libpf.BEAM:
		size = unsafe.Sizeof(support.BEAMProcInfo{})
	case libpf.APMInt:
		size = unsafe.Sizeof(support.ApmIntProcInfo{})
	case libpf.GoLabels:
		size = unsafe.Sizeof(support.GoLabelsOffsets{})
	default:
		// For unknown types, we can't determine the size
		return fmt.Errorf("unknown interpreter type: %d", typ)
	}

	// Copy the data from unsafe.Pointer to a byte slice
	dataBytes := unsafe.Slice((*byte)(data), size)
	// Make a copy to ensure we own the data
	dataCopy := make([]byte, len(dataBytes))
	copy(dataCopy, dataBytes)

	// Base64 encode the binary data
	dataBase64 := base64.StdEncoding.EncodeToString(dataCopy)

	e.Data = dataBase64
	return nil
}

func (e *ebpfMock) UpdateStackDeltaPages(fileID host.FileID, numDeltasPerPage []uint16, mapID uint16, firstPageAddr uint64) error {
	return nil
}

func (e *ebpfMock) UpdateUnwindInfo(index uint16, info stackdeltatypes.UnwindInfo) error {
	return nil
}

// traceReporterStub is a stub implementation of reporter.TraceReporter
type traceReporterStub struct{}

func (tr traceReporterStub) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	return nil
}

func analyzeFile(f string, pid int, includeTracers types.IncludedTracers) error {
	ebpf := &ebpfMock{}
	ctx := context.Background()
	sdp := elfunwindinfo.NewStackDeltaProvider()
	traceReporter := traceReporterStub{}

	pm, err := processmanager.New(ctx, includeTracers, time.Minute, ebpf, traceReporter, nil, sdp, false, libpf.Set[string]{})
	if err != nil {
		return err
	}
	defer pm.Close()

	// Get the actual process
	pr := process.New(libpf.PID(pid), libpf.PID(pid))
	defer pr.Close()

	// Get all mappings from the process
	mappings, _, err := pr.GetMappings()
	if err != nil {
		return fmt.Errorf("failed to get process mappings: %w", err)
	}

	// Find the first executable mapping that matches the file path
	var matchingMapping *process.Mapping
	for i := range mappings {
		m := &mappings[i]
		if m.Path.String() == f && m.IsExecutable() {
			matchingMapping = m
			break
		}
	}

	if matchingMapping == nil {
		return fmt.Errorf("file %s not found in process %d executable mappings", f, pid)
	}

	// Find the libc executable mapping (needed for Python, Perl, etc.)
	var libcMapping *process.Mapping
	for i := range mappings {
		m := &mappings[i]
		if m.IsExecutable() && libc.IsPotentialTSDDSO(m.Path.String()) {
			libcMapping = m
			break
		}
	}

	// Process libc mapping first if found (needed for interpreter libc info)
	if libcMapping != nil {
		err = pm.NewFrameMapping(pr, libcMapping)
		if err != nil {
			log.Debugf("Failed to create frame mapping for libc: %v", err)
			// Continue anyway - libc might not be critical for all interpreters
		}
	}

	// Call NewFrameMapping which will detect and load interpreter data
	// This will trigger UpdateProcData calls which we capture in the mock
	err = pm.NewFrameMapping(pr, matchingMapping)
	if err != nil {
		return fmt.Errorf("failed to create frame mapping: %w", err)
	}

	// Extract the captured proc data from the mock
	if ebpf.Data == "" {
		return fmt.Errorf("no interpreter data found (no UpdateProcData calls were made)")
	}

	if ebpf.EbpfProgIndex == 0 {
		return fmt.Errorf("neither UpdateInterpreterOffsets nor UpdatePidInterpreterMapping callback was called")
	}

	jsonData, err := json.MarshalIndent(ebpf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal proc data to JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func main() {
	var file = flag.String("file", "", "The file to analyze for interpreter data")
	var pid = flag.Int("pid", 0, "The process loading the files")
	var tracers = flag.String("tracers", "python,hotspot,v8", "The tracers to enable")
	var verbose = flag.Bool("v", false, "Enable debug level logging")

	flag.Parse()

	if *verbose {
		log.SetDebugLogger()
	}

	if *pid == 0 {
		log.Fatalf("pid must be provided and non-zero")
	}

	if *file == "" {
		log.Fatalf("file must be provided and non-empty")
	}

	includeTracers, _ := tracertypes.Parse(*tracers)

	if err := analyzeFile(*file, *pid, includeTracers); err != nil {
		log.Fatalf("%s: %s\n", *file, err)
	}
}
