FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y xxd gcc make libxml2 libxml2-dev xmlsec1 libxmlsec1-dev libxmlsec1-openssl

COPY tests/ /var/tmp

COPY pkirpmsign.c /var/tmp/current_test
COPY pkirpmverify.c /var/tmp/current_test
COPY Makefile /var/tmp/current_test

WORKDIR /var/tmp/current_test

RUN make

CMD ["bash", "/var/tmp/current_test/test_in_container.sh"]

