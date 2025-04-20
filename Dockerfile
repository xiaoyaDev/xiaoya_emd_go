FROM golang:1.22-alpine3.21 as builder

RUN apk add --no-cache git sqlite gcc musl-dev

WORKDIR /builder

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o xiaoya_emd main.go

FROM alpine:3.21

ENV TZ=Asia/Shanghai

RUN set -ex && \
    apk add --no-cache \
        bash \
        tini \
        tzdata && \
    rm -rf \
        /root/.cache \
        /tmp/*

COPY --from=builder /builder/xiaoya_emd /app/xiaoya_emd
COPY config.json /app/config.json

WORKDIR /app

ENTRYPOINT ["tini", "-g", "--", "/app/xiaoya_emd"]

CMD ["--media", "/media"]

EXPOSE 8080