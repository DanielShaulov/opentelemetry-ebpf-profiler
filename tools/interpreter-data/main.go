// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// A command-line tool to parse interpreter data from given ELF files.
package main

import (
	"flag"
	"fmt"
	"unsafe"

	"github.com/parinpan/magicjson"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	"go.opentelemetry.io/ebpf-profiler/processmanager/execinfomanager"
	"go.opentelemetry.io/ebpf-profiler/tracer/types"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// mock of EbpfHandler, saves some data on updates
type ebpfMock struct {
	interpreterProgIndex uint16
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
	log.Infof("UpdateInterpreterOffsets %d", ebpfProgIndex)
	e.interpreterProgIndex = ebpfProgIndex
	return nil
}

func (e *ebpfMock) UpdatePidInterpreterMapping(pid libpf.PID, prefix lpm.Prefix, interpreterType uint8, fileID host.FileID, offset uint64) error {
	return nil
}

func (e *ebpfMock) UpdatePidPageMappingInfo(pid libpf.PID, prefix lpm.Prefix, fileID uint64, bias uint64) error {
	return nil
}

func (e *ebpfMock) UpdateProcData(typ libpf.InterpreterType, pid libpf.PID, data unsafe.Pointer) error {
	return nil
}

func (e *ebpfMock) UpdateStackDeltaPages(fileID host.FileID, numDeltasPerPage []uint16, mapID uint16, firstPageAddr uint64) error {
	return nil
}

func (e *ebpfMock) UpdateUnwindInfo(index uint16, info stackdeltatypes.UnwindInfo) error {
	return nil
}

func analyzeFile(f string, includeTracers types.IncludedTracers) error {
	ebpf := &ebpfMock{}
	eim, err := execinfomanager.NewExecutableInfoManager(elfunwindinfo.NewStackDeltaProvider(), ebpf, includeTracers)
	if err != nil {
		return err
	}
	interpreterData := eim.DetectAndLoadInterpData(f)
	if interpreterData == nil {
		return fmt.Errorf("no interpreter data found")
	}

	log.Infof("ebpfMock: %+v", ebpf)

	// Use magicjson to marshal the interpreter data (including private fields)
	jsonData, err := magicjson.Marshal(interpreterData)
	if err != nil {
		return fmt.Errorf("failed to marshal interpreter data to JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func main() {
	flag.Parse()
	includeTracers, _ := tracertypes.Parse("python,hotspot,v8")

	for _, f := range flag.Args() {
		if err := analyzeFile(f, includeTracers); err != nil {
			log.Errorf("%s: %s\n", f, err)
		}
	}
}
