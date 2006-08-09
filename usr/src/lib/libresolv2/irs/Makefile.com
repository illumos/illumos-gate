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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY= irs.a
VERS= .1

IRSDYNOBJS=	nis_nw.o	nis_pr.o	nis_pw.o	nis_sv.o \
		nis.o		nis_gr.o	nis_ho.o	nis_ng.o \
		irp.o		irpmarshall.o	irp_ho.o	irp_nw.o \
		irp_pr.o	irp_sv.o	irp_gr.o	irp_ng.o \
		irp_pw.o	getnetent.o	getpwent_r.o	getgrent_r.o \
		getservent_r.o	getnetent_r.o	getnetgrent_r.o	getgrent.o \
		getnetgrent.o	getprotoent.o	getpwent.o	getservent.o \
		getprotoent_r.o	getnameinfo.o	gai_strerror.o

SUNWOBJS=	sunw_irs_nis_acc.o

OBJECTS=	$(IRSDYNOBJS) $(SUNWOBJS)

include ../../../Makefile.lib

LIBNAME=	$(LIBRARY:%.a=%)
LIBS=		$(DYNLIB)
LDLIBS +=	-lresolv -lnsl -lsocket -lc

MAPFILES =	../mapfile-vers

SRCDIR=		../../common/irs
SRCS=		$(IRSDYNOBJS:%.o=$(SRCDIR)/%.c) \
		$(SUNWOBJS:%.o=../../common/sunw/%.c)

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
CRYPTFLAGS=	-DCYLINK_DSS -DHMAC_MD5 -DUSE_MD5 -DDNSSAFE

CPPFLAGS +=	$(CRYPTFLAGS) $(CRYPTINCL)
CPPFLAGS +=	-D_SYS_STREAM_H -D_REENTRANT -DSVR4 -DSUNW_OPTIONS \
		-D__SUNW_IRS_INIT_NODEFINE $(SOLCOMPAT) \
		-I../../include -I../../../common/inc

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

$(ROOTLIBDIR) $(ROOTLIBDIR64):
	$(INS.dir)

include ../../../Makefile.targ

pics/%.o: ../../common/sunw/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
