# This Dockerfile is not currently published as an image, it only exists to
# test the build in a clean local development environment.
FROM golang:1-buster
RUN apt-get update \
    && apt-get install -y libpcsclite-dev \
    && apt-get clean
WORKDIR /src
COPY . .
RUN go build ./cmd/piv-agent
