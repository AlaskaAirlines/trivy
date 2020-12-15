FROM aquasec/trivy:0.14.0

RUN apk --no-cache add ca-certificates git
# RUN chmod 777 bin/trivy
RUN echo $(ls -l ./bin/)
RUN echo $(ls -l /usr/local/bin/)
COPY ./bin/trivy /usr/local/bin/trivy
RUN echo $(ls -l /usr/local/bin/)
COPY contrib/*.tpl contrib/
RUN adduser -D TheGrinch
USER TheGrinch
ENTRYPOINT ["trivy"]
