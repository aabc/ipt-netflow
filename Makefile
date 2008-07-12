obj-m = ipt_NETFLOW.o
KVERSION = $(shell uname -r)
KDIR = /lib/modules/$(KVERSION)/build
IPTDIR = ../iptables-1.3.7-20070329
IPTABLES_VERSION = 1.3.7-20070329
all:
	make -C $(KDIR) M=$(PWD) modules
minstall:
	make -C $(KDIR) M=$(PWD) modules_install
clean:
	make -C $(KDIR) M=$(PWD) clean

libipt_NETFLOW.so: libipt_NETFLOW.c
	gcc -O2 -Wall -Wunused -I$(KDIR)/include -I$(IPTDIR)/include -DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\" -fPIC -o libipt_NETFLOW_sh.o -c libipt_NETFLOW.c
	gcc -shared  -o libipt_NETFLOW.so libipt_NETFLOW_sh.o

linstall: ipt_NETFLOW.ko libipt_NETFLOW.so
	cp -a libipt_NETFLOW.so /usr/local/lib/iptables/

install: minstall linstall

load: all
	insmod ipt_NETFLOW.ko active_timeout=5
	iptables -A OUTPUT -d 1.0.0.0/8 -j NETFLOW

unload:
	iptables -D OUTPUT -d 1.0.0.0/8 -j NETFLOW
	rmmod ipt_NETFLOW.ko
