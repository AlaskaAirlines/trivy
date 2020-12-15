FROM gcr.io/aag-anthos-poc17-app/trivy:PreBaked
RUN apk --no-cache add ca-certificates git
COPY bin/trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
RUN adduser -D TheGrinch
USER TheGrinch
ENTRYPOINT ["trivy"]
