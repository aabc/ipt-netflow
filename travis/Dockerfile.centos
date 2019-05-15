# https://hub.docker.com/_/centos/

ARG OS_VERSION

FROM centos:$OS_VERSION

RUN yum -y install \
    gcc \
    make \
    kernel-devel \
    iptables-devel \
    net-snmp \
    net-snmp-devel \
    which

CMD ./configure --kdir=$(echo /usr/src/kernels/*) && make all

