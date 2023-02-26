
ARG GOVERSION=1.18

FROM golang:${GOVERSION}-alpine AS build
WORKDIR /go/src/cs-blocklist-mirror
RUN apk add --update --no-cache libc-dev make git
COPY . .
RUN make build

FROM alpine:latest
COPY --from=build  /go/src/cs-blocklist-mirror/crowdsec-blocklist-mirror /usr/local/bin/crowdsec-blocklist-mirror
COPY --from=build /go/src/cs-blocklist-mirror/config/crowdsec-blocklist-mirror.yaml /etc/crowdsec/bouncers/crowdsec-blocklist-mirror.yaml
ENTRYPOINT [ "/usr/local/bin/crowdsec-blocklist-mirror", "-c", "/etc/crowdsec/bouncers/crowdsec-blocklist-mirror.yaml"]
