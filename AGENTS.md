# AGENTS.md

## Cursor Cloud specific instructions

This repo is the **OpenTelemetry eBPF Profiler**: a Linux-only, whole-system profiler
written in Go, with a Rust symbolization workspace (`rust-crates/`) and eBPF programs in
C (`support/ebpf/`). Standard build/test/run commands live in `README.md`, `Makefile`,
and `support/ebpf/Makefile`; prefer those. Notes below are the non-obvious bits.

### Toolchain (pre-installed in the VM snapshot)

- Go (per `go.mod`), Rust `1.97.1` with the `x86_64-unknown-linux-musl` target.
- LLVM/clang **17** toolchain (`clang-17`, `llvm-link-17`, `llc-17`, `llvm-strip-17`,
  `clang-format-17`). `support/ebpf/Makefile` hardcodes the `-17` suffix, so newer clang
  will not be used unless you override `BPF_CLANG`/`BPF_LINK`/`STRIP`/`LLC`/`CLANG_FORMAT`.
- `protoc` 24.4 plus `protoc-gen-go` / `protoc-gen-go-grpc` (in `~/go/bin`, which is on
  `PATH` via `~/.bashrc`). `make generate` / `make lint` invoke these.
- `qemu-system-x86`, `bluebox`, and `crane` (in `~/go/bin`) for the QEMU integration tests.

### Build / lint / test

- Build binaries: `make ebpf-profiler` and `make otelcol-ebpf-profiler`.
- Lint: `CGO_ENABLED=1 make lint`. Format: `make format`.
- Go unit tests: `CGO_ENABLED=1 make test` (or target packages with `go test`). `CGO_ENABLED=1`
  is required because `tools/coredump` compiles the eBPF C via cgo.
- Rust tests: `cargo test` (or `make rust-tests`).
- `make test`/`make lint` run `go generate` and build several Go toolchains
  (`go1.23.7`, `go1.24.6`) for the pprof integration fixtures on first run.

### IMPORTANT: this VM's kernel cannot load the profiler's eBPF live

The Cloud VM guest kernel has **no BTF** (`/sys/kernel/btf/vmlinux` missing), no tracefs,
and restricted eBPF (`kernel.perf_event_paranoid=2`, `kernel.unprivileged_bpf_disabled=2`).
Running `./ebpf-profiler` or `./otelcol-ebpf-profiler` on the host gets through most
startup but fails at system-config analysis with
`failed to load read_kernel_function_or_task_struct: ... invalid argument`. This is an
environment limitation, not a code bug — do not chase it. The binaries still build and
their CLI/config/eBPF-load path can be exercised for smoke checks.

To validate eBPF **end to end**, use one of:

1. **Coredump harness (fast, no VM)** — runs the unwinder in userspace against real
   coredumps. Great as a "does the unwinder work" check:
   - `CGO_ENABLED=1 go test -tags osusergo,netgo -run 'TestCoreDumps/testdata/amd64/<name>' ./tools/coredump/`
   - Or print a stack trace: build `./tools/coredump` and run
     `./coredump analyze -case tools/coredump/testdata/amd64/<name>.json` (run from
     `tools/coredump/`). Each case lazily downloads a small module into `modulecache`.
2. **QEMU integration tests (real kernel)** — see below.

### Running QEMU integration tests here (caveats)

- **No `/dev/kvm`**: QEMU must run in TCG (software) emulation (slow but works; a single
  test binary boots + runs in well under a couple of minutes). `support/run-tests.sh`
  force-adds `-enable-kvm` whenever `/proc/cpuinfo` shows `vmx|svm` (true here) even though
  `/dev/kvm` is absent, which makes QEMU fail. Run from a copy of the script that also
  requires `/dev/kvm` to be present before enabling KVM.
- **No Docker**: CI fetches kernels via `docker ... ghcr.io/cilium/ci-kernels`. Use `crane`
  instead: `crane export ghcr.io/cilium/ci-kernels:<ver> - | tar -C <dir>/<ver> -x boot/`
  then move `boot/vmlinuz` to `<dir>/<ver>/vmlinuz` (matches `run-tests.sh`).
- Build one test binary (don't run the whole matrix), e.g. the tracer:
  `CGO_ENABLED=0 go test -ldflags='-extldflags=-static' -trimpath -c -tags osusergo,netgo,static_build,integration -o <dir>/tracer.test ./tracer`
- `support/run-tests.sh` globs `*.test` in the current dir and expects the kernel at
  `ci-kernels/<ver>/vmlinuz` (override the dir with `KERN_DIR`). Put only the one `.test`
  you want to run in that dir.
