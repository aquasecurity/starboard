FROM alpine:3.16.2

RUN adduser -u 10000 -D -g '' starboard starboard

COPY starboard /usr/local/bin/starboard

USER starboard

ENTRYPOINT ["starboard"]
