FROM scratch

COPY starboard /usr/local/bin/starboard

ENTRYPOINT ["starboard"]
