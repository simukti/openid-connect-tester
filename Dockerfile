# build stage
FROM golang:1.26.2-trixie AS builder
WORKDIR /go/src/app
COPY . .
ENV CGO_ENABLED=0
RUN go build -x -trimpath -pgo=auto -gcflags='-m=3' \
    -mod=vendor -tags "usergo,netgo,linux" \
    -ldflags "-extldflags=-static -w -s -v" \
    -o build/server ./main.go
# final image
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=builder /go/src/app/build/server /app/server
WORKDIR /app
CMD ["./server"]
