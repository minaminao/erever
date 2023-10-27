# docker build . -t erever
# docker run -it erever
FROM python:3.12-alpine

RUN apk update && apk add \
    build-base \
    py3-pip \
    git \
    bash \
    vim

COPY . /erever
WORKDIR /erever
RUN pip install .

