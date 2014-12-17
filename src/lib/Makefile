##### Server-level Makefile for KX509 #####
##### $Id: Makefile.in,v 1.1.1.1 2007/01/26 15:57:05 kwcoffman Exp $

SHELL		= /bin/sh


srcdir		= .


SHELL		= /bin/sh

CC		= gcc

INSTALL		= /usr/bin/install -c
INSTALL_PROGRAM	= ${INSTALL}
INSTALL_DATA	= ${INSTALL} -m 644

AR		= /usr/bin/ar
RANLIB		= ranlib
RM		= /bin/rm -f

DEFS		= -DHAVE_CONFIG_H
LIBS		=  -lbsd -lnsl

prefix		= /usr/local
binprefix	=
exec_prefix	= ${prefix}
bindir		= ${exec_prefix}/bin
includedir	= ${prefix}/include
manprefix	=
man1dir		= ${prefix}/man/man1
man3dir		= ${prefix}/man/man3
man8dir		= ${prefix}/man/man8

# The following need to be defined in order
# to locate the Krb include files and libraries

KRB_BASE	= /usr/kerberos
OPENSSL_BASE	= /usr

INCLUDE 	= -I$(OPENSSL_BASE)/include -I.. -I$(srcdir)

CFLAGS		= -DWRITE_CERT
LIB_CFLAGS	= -DLINUX $(CCOPT) $(DEFS) $(DEFINE) $(INCLUDE) $(CFLAGS)

KX_LIB_OBJS 	= udp_nb_socket.o	udp_nb_sockets.o 		\
		  udp_nb_bind.o		udp_nb_connect.o 		\
		  udp_nb_select.o					\
		  udp_nb_send.o		udp_nb_sendto.o 		\
		  udp_nb_recv.o		udp_nb_recvfrom.o		\
		  msg.o 						\
		  kx509_asn.o		kx509_ck.o

PROGS		= libkx.a

.c.o:
	@$(RM) $@
	$(CC) $(LIB_CFLAGS) -c $<

all:	$(PROGS)

tags:
	ctags $(SRC)

clean:
	$(RM) *.o $(PROGS)

libkx.a: $(KX_LIB_OBJS) 
	$(RM) $@
	$(AR) -q $@ $(KX_LIB_OBJS)
	$(RANLIB) $@

install:
