FROM alpine:3.17

RUN apk update && apk upgrade

RUN adduser -u 10000 -D -g '' starboard starboard

COPY starboard-operator /usr/local/bin/starboard-operator

USER starboard

ENTRYPOINT ["starboard-operator"]
