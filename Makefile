# Distribution Makefile for iptdomain
#

BINDIR = /usr/sbin
CONFDIR = /etc/iptdomain
MANDIR = /usr/share/man/man8

USERCOMMAND = bin/iptdomainctl
DAEMON = bin/iptdomain
MANPAGES = $(wildcard src/*.8)
ACL = $(wildcard acl/*.acl)

.PHONY: default install clean

default: $(DAEMON)

$(DAEMON): $(wildcard src/*.c)
	gcc -g -Wall -o $@ $^ -lnetfilter_queue

# Installing the control script in $(INSTALLDIR)

install: $(DAEMON) $(USERCOMMAND)
	install -t $(BINDIR) $(DAEMON) $(USERCOMMAND)
	install -t $(MANDIR) $(MANPAGES)
	mkdir -p $(CONFDIR)/blocked $(CONFDIR)/acl
	install -t $(CONFDIR)/acl $(ACL)

clean:
	rm -f bin/iptdomain
