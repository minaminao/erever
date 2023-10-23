# docker build . -t erever
# docker run -it erever
FROM python:3.11-alpine

RUN apk update && apk add \
    vim \
    py3-pip \
    git \
    bash

COPY . /erever
WORKDIR /erever
RUN pip install .

