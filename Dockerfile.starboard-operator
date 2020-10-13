FROM alpine:3.12

RUN adduser -u 10000 -D -g '' starboard starboard

COPY starboard-operator /usr/local/bin/starboard-operator

USER starboard

ENTRYPOINT ["starboard-operator"]
