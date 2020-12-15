FROM aquasec/trivy:0.14.0

RUN apk --no-cache add ca-certificates git
COPY bin/trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
RUN adduser -D TheGrinch
USER TheGrinch
ENTRYPOINT ["trivy"]
