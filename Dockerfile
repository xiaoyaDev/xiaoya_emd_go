FROM golang:1.22-alpine3.21 as builder

WORKDIR /builder

COPY . .

RUN go mod download

RUN go build -o xiaoya_emd

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

WORKDIR /app

ENTRYPOINT ["tini", "-g", "--", "/app/xiaoya_emd"]

CMD ["--media", "/media"]

EXPOSE 8080