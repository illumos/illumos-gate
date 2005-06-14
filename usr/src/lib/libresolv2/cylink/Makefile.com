#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libresolv2/cylink/Makefile.com
#

LIBRARY= cylink.a
VERS= .1

DSTOBJS=	cylink_link.o

CYLINKOBJS=	bits.o		dss.o		rand.o		bn.o \
		lbn00.o		lbnmem.o	sha.o		bn00.o \
		legal.o		swap.o		ctk_prime.o	math.o

OBJECTS=	$(DSTOBJS) $(CYLINKOBJS)

# include library definitions
include ../../../Makefile.lib

LIBNAME=	$(LIBRARY:%.a=%)
LIBS=		$(DYNLIB)
LDLIBS +=	-lresolv -lc

MAPDIR =	../spec/$(TRANSMACH)
SPECMAPFILE =	$(MAPDIR)/mapfile
SRCDIR=		../../common/cylink
SRCS=		$(DSTOBJS:%.o=../../common/dst/%.c) \
		$(CYLINKOBJS:%.o=$(SRCDIR)/%.c)

ROOTLIBDIR=	$(ROOT)/usr/lib/dns
ROOTLIBDIR64=	$(ROOT)/usr/lib/dns/$(MACH64)

# Local Libresolv definitions
SOLCOMPAT =	-Dgethostbyname=res_gethostbyname \
	-Dgethostbyaddr=res_gethostbyaddr -Dgetnetbyname=res_getnetbyname \
	-Dgethostbyname2=res_gethostbyname2\
	-Dgetnetbyaddr=res_getnetbyaddr -Dsethostent=res_sethostent \
	-Dendhostent=res_endhostent -Dgethostent=res_gethostent \
	-Dsetnetent=res_setnetent -Dendnetent=res_endnetent \
	-Dgetnetent=res_getnetent -Dsocket=_socket

CRYPTINCL=	-I../../common/cylink -I../../common/dnssafe
CRYPTFLAGS=	-DCYLINK_DSS -DHMAC_MD5 -DUSE_MD5 -DDNSSAFE \
		-D__SUNW_DST_INIT_NODEFINE

CPPFLAGS +=	$(CRYPTFLAGS) $(CRYPTINCL)
CPPFLAGS +=	-D_SYS_STREAM_H -D_REENTRANT -DSVR4 -DSUNW_OPTIONS \
		$(SOLCOMPAT) -I../../include

REDLOC=		$(ZREDLOCSYM)

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

$(ROOTLIBDIR) $(ROOTLIBDIR64):
	$(INS.dir)

include ../../../Makefile.targ

pics/%.o: ../../common/dst/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
