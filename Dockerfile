FROM golang as build

ADD . $GOPATH/src/kodix.ru/vwgr-auth-proxy

RUN    cd $GOPATH/src/kodix.ru/vwgr-auth-proxy && \
 CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o $GOPATH/bin/jwtmw .

FROM scratch
#FROM debian:stretch-slim

COPY --from=build /go/bin/jwtmw /jwtmw
COPY --from=build /go/src/kodix.ru/vwgr-auth-proxy/config.json /opt/default/config.json
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 80
ENTRYPOINT ["/jwtmw"]