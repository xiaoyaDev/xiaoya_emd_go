FROM golang:1.24-alpine3.21 as builder

RUN apk add --no-cache git sqlite gcc musl-dev

WORKDIR /builder

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -v -x -ldflags="-s -w" -o xiaoya_emd main.go

FROM alpine:3.23

ENV TZ=Asia/Shanghai

RUN set -ex && \
    apk add --no-cache \
        bash \
        tini \
        ca-certificates \
        sqlite \
        tzdata && \
    rm -rf \
        /root/.cache \
        /tmp/*

COPY --from=builder /builder/xiaoya_emd /app/xiaoya_emd
COPY config.json /app/config.json

WORKDIR /app

ENTRYPOINT ["tini", "-g", "--", "/app/xiaoya_emd"]

CMD ["--media", "/media"]
