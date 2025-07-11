FROM golang:1.24 as builder

WORKDIR /workspace

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN apt-get update && apt-get install -y clang llvm libbpf-dev zlib1g-dev

RUN GOOS=linux GOARCH=amd64 go build -o ebpf_loader cmd/main.go 

FROM golang:alpine

RUN apk --no-cache add libc6-compat

COPY --from=builder /workspace/ebpf_loader .

ENTRYPOINT ["./ebpf_loader"]

CMD []
