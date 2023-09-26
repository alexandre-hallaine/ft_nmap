FROM debian:latest

RUN apt-get update && apt-get install -y build-essential libpcap-dev

WORKDIR /app
