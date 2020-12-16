FROM alpine:3.12

RUN apk --no-cache add ca-certificates git

COPY bin/trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/

# RUN mkdir -p /root/.cache && trivy --download-db-only --cache-dir /root/.cache/
RUN mkdir -p /var/lib/trivy && trivy --download-db-only --cache-dir /var/lib/trivy
RUN chmod 777 -R /var/lib/trivy/

RUN adduser -D TheGrinch
USER TheGrinch

ENTRYPOINT ["trivy"]