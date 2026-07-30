FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -o /certmgr-webhook ./*.go

FROM docker.io/library/alpine:3.23

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /certmgr-webhook .

EXPOSE 8080

CMD ["./certmgr-webhook"]