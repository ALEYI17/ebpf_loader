# InfraSight Agent (eBPF Loader)

This component of the **InfraSight** platform is a node-level agent that uses **eBPF programs** to trace system activity (e.g., syscalls like `execve`, `accept`, etc.), enriches this data, and sends it to the InfraSight server via gRPC.

It is responsible for:
- Loading and attaching eBPF programs to tracepoints
- Capturing events from the kernel
- Enriching events with user-space metadata
- Sending structured events to the server using gRPC

## 📦 Features

- Traces syscalls like `execve`, `open`, `connect`, `accept`, `chmod`.
- Uses **Cilium/ebpf** to interact with eBPF programs
- Communicates over gRPC with the InfraSight server
- Flexible design: load multiple eBPF "loaders" dynamically
- Designed for use as a container in Kubernetes or standalone

## 🧱 Technologies Used and Dependencies

- [Go](https://golang.org/) (>= 1.21)
- [Cilium eBPF](https://github.com/cilium/ebpf)
- [gRPC](https://grpc.io/)
- [Protocol Buffers](https://protobuf.dev/)
- `go:generate` to compile eBPF programs from C
- `libelf`
- `zlib`


### How to run the container with docker

```bash

docker run -it \
--privileged \
-e TRACER=accept,execve \
-e NODE_NAME=CASA \
-p 9090:9090 \
-v /var/run:/var/run:ro \
-v /sys/kernel/debug:/sys/kernel/debug:rw \
ghcr.io/aleyi17/ebpf_loader:latest \
--server-addr=server \
--server-port=8080

```
> 🔐 `--privileged` is required to load eBPF programs.

## 🛠️ Building from Source

### Clone the repository
```bash
git clone https://github.com/ALEYI17/ebpf_loader.git
cd ebpf_loader
```

### Compile the Go code
```bash
go build -o ebpf-loader ./cmd/main.go
```

### Compile the eBPF programs
Each eBPF program is in `bpf/<name>/`, with a corresponding `generate.go` file.

To compile all:
```bash
go generate ./bpf/...
```

> ⚠️ Requires `clang` and `llvm`.


## 🧪 Compiling Protobuf
If you modify the `.proto` file, recompile Go stubs:

```bash
cd internal/grpc/pb && protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ebpf_event.proto
```

### ✅ Required Parameters

| Parameter     | Flag              | Env Variable   | Description                               |
|---------------|------------------|----------------|-------------------------------------------|
| Tracers       | `--tracer`       | `TRACER`       | Comma-separated list of enabled probes (e.g. `execve,open`) |
| Server Addr   | `--server-addr`  | `SERVER_ADDR`  | Address of gRPC server                    |
| Server Port   | `--server-port`  | `SERVER_PORT`  | Port of gRPC server                       |
| Prometheus Port  | `--prometheus-port`    | `PROMETHEUS_PORT`    | Port to expose Prometheus metrics (default: `9090`)                         |
| Node Name     | _(not a flag)_   | `NODE_NAME`    | Optional. Used for tagging node origin. Falls back to `os.Hostname()` if unset |

### 💡 Example CLI
> ⚠️ Note: You must run the agent as root or with sudo to load eBPF programs.
```bash
sudo ./ebpf-loader \
  --tracer=execve,accept \
  --server-addr=10.0.0.1 \
  --server-port=8080
```

Or with environment variables:

```bash
export TRACER=execve,accept
export SERVER_ADDR=10.0.0.1
export SERVER_PORT=8080
sudo ./ebpf-loader
```

## 📈 Prometheus Metrics

The `ebpf_loader` exposes internal metrics on `/metrics` (default port `:9090`) using Prometheus format. These are useful for observability, troubleshooting, and performance monitoring.

> You can scrape this with Prometheus or inspect manually.

### 📊 Available Metrics

| Name                                     | Labels             | Description                                                             |
| ---------------------------------------- | ------------------ | ----------------------------------------------------------------------- |
| `infrasight_enricher_cache_hits_total`   | `source`           | Cache hits during enrichment (e.g., `"container"`, `"user"`)            |
| `infrasight_enricher_cache_misses_total` | `source`           | Cache misses during enrichment                                          |
| `infrasight_grpc_messages_sent_total`    | `tracer`, `status` | Total gRPC messages sent (`status`: `"success"` or `"error"`)           |
| `infrasight_grpc_send_latency_seconds`   | `tracer`           | Histogram of gRPC send latencies                                        |
| `infrasight_tracer_events_total`         | `tracer`           | Total number of events read from each eBPF loader                       |
| `infrasight_tracer_errors_total`         | `tracer`, `type`   | Errors during event processing (e.g., decode failure, ringbuffer issue) |


## 📚 Related Repositories

This is part of the **[InfraSight](https://github.com/ALEYI17/InfraSight)** platform:

- [`infrasight-controller`](https://github.com/ALEYI17/infrasight-controller): Kubernetes controller to manage agents
- [`ebpf_loader`](https://github.com/ALEYI17/ebpf_loader): Agent that collects and sends eBPF telemetry from nodes
- [`ebpf_server`](https://github.com/ALEYI17/ebpf_server): Receives and stores events (e.g., to ClickHouse)
- [`ebpf_deploy`](https://github.com/ALEYI17/ebpf_deploy): Helm charts to deploy the stack
- [`InfraSight_ml`](https://github.com/ALEYI17/InfraSight_ml): Machine learning models for anomaly detection.
- [`InfraSight_sentinel`](https://github.com/ALEYI17/InfraSight_sentinel): Rules engine that generates alerts based on predefined detection logic.

