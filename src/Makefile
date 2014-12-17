##### Top-level Makefile for KX509 #####
##### $Id: Makefile.in,v 1.1.1.1 2007/01/26 15:57:04 kwcoffman Exp $

SHELL= /bin/sh


srcdir= .


SHELL= /bin/sh

CC= gcc

INSTALL= /usr/bin/install -c
INSTALL_PROGRAM= ${INSTALL}
INSTALL_DATA= ${INSTALL} -m 644

AR= /usr/bin/ar
RANLIB= ranlib
RM= /bin/rm -f

DEFS= -DHAVE_CONFIG_H
LIBS=  -lbsd -lnsl

prefix= /usr/local
binprefix=
exec_prefix= ${prefix}
bindir= ${exec_prefix}/bin
includedir= ${prefix}/include
manprefix=
man1dir= ${prefix}/man/man1
man3dir= ${prefix}/man/man3
man8dir= ${prefix}/man/man8

##### End of system configuration section #####

# Subdirectories with makefiles
SUBDIRS= lib  client

##### Targets #####

all:
	@for i in ${SUBDIRS}; do cd $$i; ${MAKE} ; cd .. ; done

clean:
	@for i in ${SUBDIRS}; do (cd $$i; exec ${MAKE} clean ) done

install:
	@for i in ${SUBDIRS}; do (cd $$i; exec ${MAKE} install ) done

# Useful sub targets

libkx.a:
	cd lib; ${MAKE} ${MDEFINES} $@

kca:
	cd server; ${MAKE} ${MDEFINES} $@

kx509:
	cd client; ${MAKE} ${MDEFINES} $@

Makefile: Makefile.in config.status
	./config.status

config.status: configure
	./config.status --recheck
