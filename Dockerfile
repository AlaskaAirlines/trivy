FROM alpine:3.12

RUN apk --no-cache add ca-certificates git

COPY bin/trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/

RUN chmod 777 /usr/local/bin/trivy

RUN mkdir -p /root/.cache && trivy --download-db-only --cache-dir /root/.cache/
RUN mkdir -p /var/lib/trivy && trivy --download-db-only --cache-dir /var/lib/trivy

COPY bin/service_auth.json /var/lib/service_auth.json

RUN chmod 777 -R /var/lib/trivy/
RUN chmod 777 -R /root/.cache/

# Required for GKE - https://github.com/aquasecurity/trivy#gcr-google-container-registry
ENV TRIVY_USERNAME=''
ENV GOOGLE_APPLICATION_CREDENTIALS=/var/lib/service_auth.json

RUN adduser -D TheGrinch
RUN chown TheGrinch:TheGrinch -R /root
USER TheGrinch

ENTRYPOINT ["trivy"]
