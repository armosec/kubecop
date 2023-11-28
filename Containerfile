FROM golang:1.21.1-alpine3.18 as builder
RUN apk add --no-cache git
WORKDIR /go/src/app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o kubecop ./cmd/main.go

FROM alpine:3.18
COPY --from=builder /go/src/app/kubecop /kubecop
ENTRYPOINT ["/kubecop"]
