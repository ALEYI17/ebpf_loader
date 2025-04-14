## eBPF Loader 

### How to run the container

```bash

docker run -it \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  --privileged \
  loader:latest

```
