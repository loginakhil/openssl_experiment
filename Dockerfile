FROM ubuntu:bionic

RUN apt update && apt install -y build-essential libssl-dev openssl

WORKDIR  /app

COPY . /app

CMD ["bash"]
