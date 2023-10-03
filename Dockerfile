FROM golang:1.20.6-alpine3.18 as builder
WORKDIR /go/src/app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o kubecop ./cmd/main.go

FROM alpine:3.18
RUN apk add libseccomp
COPY --from=builder /go/src/app/kubecop /kubecop
ENTRYPOINT ["/kubecop"]
