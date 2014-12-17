##### Client-level Makefile for KX509 #####
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

DEFS		= -DHAVE_CONFIG_H -DLINUX
CFLAGS		= -DWRITE_CERT  -DUSE_KRB5
LDFLAGS		= 
SHLIB_SUFFIX	= so
SHLIB_PGM	= $(CC) -shared

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
# to locate the Krb5, Krb4 and OpenSSL include files and libraries

KRB_BASE	= /usr/kerberos
OPENSSL_BASE	= /usr

#
# COMPILE-TIME
#

KRB_INCS	=  -I/usr/include

INCLUDE 	= -I$(OPENSSL_BASE)/include $(KRB_INCS) \
			-I$(srcdir) -I$(srcdir)/../lib -I..

CLIENT_CFLAGS	= $(DEFS) $(DEFINE) $(INCLUDE) $(CCOPT) $(CFLAGS)

#
# LINK-TIME
#

# N.B.	Avoid using (Solaris) K5 shared libs for KX509 -- silent DES collisions
#	cause problems that are avoided by statically linking K5 components
#	BILLDO 2001.0610

KRB_LIBS	= -Wl,-rpath /usr/lib -L/usr/lib -lkrb5 -lk5crypto -lcom_err -lcrypt -lresolv
OPENSSL_LIBS	= -Wl,-rpath /usr/lib -L$(OPENSSL_BASE)/lib -L$(OPENSSL_BASE) -lcrypto
KX_LIBS		= ../lib/libkx.a
EX_LIBS		= -lcrypt -lresolv
LIBS		= $(KX_LIBS) $(OPENSSL_LIBS) $(KRB_LIBS) $(EX_LIBS) 


KX509_OBJS 	= kx509.o debug.o getcert.o get_kca_list.o get_realm.o \
			load_dlls.o store_in_cc.o store_tkt.o materialize_cert.o

LIBKX509_OBJS 	= kx509_lib.o debug.o getcert_lib.o get_kca_list.o get_realm.o \
			load_dlls.o store_in_cc_lib.o store_tkt.o materialize_cert.o

PROGS		= kx509 kxlist 

all:	$(PROGS)

tags:
	ctags $(SRC)

clean:
	$(RM) *.o $(PROGS)


kx509: $(KX509_OBJS) $(KX_LIBS)
	$(RM) kx509
	$(CC) -o kx509 $(LDFLAGS) $(CCOPT) $(CFLAGS) $(KX509_OBJS) $(LIBS)

kxlist: kxlist.o $(KX_LIBS)
	$(RM) kxlist
	$(CC) -o kxlist $(LDFLAGS) $(CCOPT) $(CFLAGS) kxlist.o $(LIBS)

libkx509.$(SHLIB_SUFFIX): $(LIBKX509_OBJS) $(KX_LIBS)
	$(RM) $@
	$(SHLIB_PGM) -o $@ $(LIBKX509_OBJS) $(KX_LIBS) @EXTRA_KX_LIBS@

install: kx509 kxlist
	$(INSTALL_PROGRAM) kx509 $(bindir)
	$(INSTALL_PROGRAM) kxlist $(bindir)

.c.o:
	@$(RM) $@
	$(CC) $(CLIENT_CFLAGS) -c $<

kx509_lib.o : kx509.c
	@$(RM) $@
	$(CC) $(CLIENT_CFLAGS) -DKX509_LIB -c $< -o $@

getcert_lib.o: getcert.c
	@$(RM) $@
	$(CC) $(CLIENT_CFLAGS) -DKX509_LIB -c $< -o $@

store_in_cc_lib.o: store_in_cc.c
	@$(RM) $@
	$(CC) $(CLIENT_CFLAGS) -DKX509_LIB -c $< -o $@

materialize_cert.o: materialize_cert.c
	@$(RM) $@
	$(CC) $(CLIENT_CFLAGS) -DKX509_LIB -c $< -o $@

