#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
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

MAPFILES =	../mapfile-vers

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
		$(SOLCOMPAT) -I../../include -I../../../common/inc

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

$(ROOTLIBDIR) $(ROOTLIBDIR64):
	$(INS.dir)

include ../../../Makefile.targ

pics/%.o: ../../common/dst/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
