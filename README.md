## eBPF Loader 

### How to run the container with docker

```bash

docker run -it \
--privileged \
-e TRACER=accept,execve \
-e NODE_NAME=CASA \
-v /var/run:/var/run:ro \
-v /sys/kernel/debug:/sys/kernel/debug:rw \
ghcr.io/aleyi17/ebpf_loader:latest \
--server-addr=server \
--server-port=8080

```
### How to compile the proto

```bash
cd internal/grpc/pb && protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ebpf_event.proto
```
