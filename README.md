## eBPF Loader 

### How to run the container

```bash

docker run -it \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  --privileged \
  loader:latest

cd internal/grpc/pb && protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ebpf_event.proto
```
