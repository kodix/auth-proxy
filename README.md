# Auth Proxy
Parse and verify JWT-token, replace it with X-Auth headers.
[![Build Status](https://travis-ci.org/kodix/auth-proxy.svg)](https://travis-ci.org/kodix/auth-proxy)

## Usage
Run with '-h' argument

## Cache clearing
For clear cached public keys send HUP signal

## Example
With docker: Run in command line from repository directory 
`dep ensure`
`docker build -t auth .`
`docker run --rm -p 1499:80 auth -addr :80 -c /opt/default/config.json -v 3 -cap 100`