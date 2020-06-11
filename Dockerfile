FROM golang:1.14.0 AS build
WORKDIR /go/src/github.com/aquasecurity/starboard/
COPY go.mod go.sum ./
COPY kube/ kube/
COPY pkg/ pkg/
COPY cmd/ cmd/
ARG STARBOARD_VERSION
RUN GO111MODULE=on CGO_ENABLED=0 go build -o ./bin/starboard ./cmd/starboard/main.go

FROM alpine:3.11 AS run
WORKDIR /opt/starboard/
# add GNU ps for -C, -o cmd, and --no-headers support
RUN apk --no-cache add procps

# Openssl is used by OpenShift tests
RUN apk --no-cache add openssl

ENV PATH=$PATH:/usr/local/mount-from-host/bin

COPY --from=build /go/src/github.com/aquasecurity/starboard/bin/starboard /usr/local/bin/starboard
COPY entrypoint.sh .
ENTRYPOINT ["./entrypoint.sh"]
CMD ["install"]

# Build-time metadata as defined at http://label-schema.org
ARG BUILD_DATE
ARG VCS_REF
LABEL org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.name="starboard" \
    org.label-schema.description="Run the Starboard tests" \
    org.label-schema.url="https://github.com/aquasecurity/starboard" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/aquasecurity/starboard" \
    org.label-schema.schema-version="0.2.1"
