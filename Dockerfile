# docker build . -t erever
# docker run -it erever
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt update -y
RUN apt install -y \
    python3 \
    python-is-python3 \
    python3-pip \
    vim

COPY . /erever
WORKDIR /erever
RUN pip install .