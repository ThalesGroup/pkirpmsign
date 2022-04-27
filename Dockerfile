FROM ubuntu:20.04

RUN apt-get update -y
RUN apt-get install --fix-missing -y xxd gcc make libxml2 libxml2-dev xmlsec1 libxmlsec1-dev libxmlsec1-openssl gettext

COPY tests/ /var/tmp

COPY pkirpmsign.c /var/tmp/current_test
COPY pkirpmverify.c /var/tmp/current_test
COPY Makefile /var/tmp/current_test
COPY po /var/tmp/current_test/po

WORKDIR /var/tmp/current_test

RUN make

CMD ["bash", "/var/tmp/current_test/test_in_container.sh"]

