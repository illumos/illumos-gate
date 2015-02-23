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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

LIBRARY= libresolv.a
VERS= .2

BSDOBJS=   	putenv.o	strcasecmp.o	strsep.o \
		ftruncate.o	readv.o		strdup.o	strtoul.o \
		gettimeofday.o	setenv.o	strerror.o	utimes.o \
		mktemp.o	setitimer.o	strpbrk.o	writev.o

DSTOBJS=	dst_api.o	support.o	hmac_link.o 

# inet_addr, inet_pton, inet_ntop, and inet_ntoa removed due to overlap with 
# libnsl
INETOBJS= 	inet_net_pton.o	inet_neta.o	inet_lnaof.o \
		inet_netof.o 	nsap_addr.o	inet_makeaddr.o	\
		inet_network.o	inet_net_ntop.o	inet_cidr_ntop.o \
		inet_cidr_pton.o 		inet_data.o

# build only the IRS objects that the ISC libbind's make would 
IRSTHROBJS=	gethostent_r.o	getnetent_r.o 	getnetgrent_r.o \
		getprotoent_r.o	getservent_r.o
IRSOBJS=	${IRSTHROBJS} \
		dns.o		dns_ho.o	dns_nw.o	dns_pr.o \
		dns_sv.o	gai_strerror.o	gen.o		gen_ho.o \
		gen_ng.o	gen_nw.o	gen_pr.o	gen_sv.o \
		getaddrinfo.o	gethostent.o	getnameinfo.o	getnetent.o \
		getnetgrent.o	getprotoent.o	getservent.o 	hesiod.o \
		irp.o		irp_ho.o	irp_ng.o 	irp_nw.o \
		irp_pr.o	irp_sv.o	irpmarshall.o	irs_data.o \
		lcl.o		lcl_ho.o	lcl_ng.o	lcl_nw.o \
		lcl_pr.o 	lcl_sv.o	nis.o		nul_ng.o \
		util.o

ISCOBJS=	assertions.o	base64.o	bitncmp.o	ctl_clnt.o \
		ctl_p.o 	ctl_srvr.o	ev_connects.o	ev_files.o \
		ev_streams.o	ev_timers.o	ev_waits.o	eventlib.o \
		heap.o		hex.o 		logging.o	memcluster.o \
		movefile.o	tree.o

NAMESEROBJS=	ns_date.o	ns_name.o	ns_netint.o	ns_parse.o \
		ns_print.o	ns_samedomain.o	ns_sign.o	ns_ttl.o \
		ns_verify.o	ns_rdata.o	ns_newmsg.o

RESOLVOBJS=	herror.o	mtctxres.o	res_comp.o	res_data.o \
		res_debug.o	res_findzonecut.o		res_init.o \
		res_mkquery.o	res_mkupdate.o	res_query.o	res_send.o \
		res_sendsigned.o		res_update.o

SUNWOBJS=	sunw_mtctxres.o	sunw_updrec.o sunw_wrappers.o

OBJECTS=	$(BSDOBJS) $(DSTOBJS) $(INETOBJS) $(IRSOBJS) $(ISCOBJS) \
		$(NAMESEROBJS) $(RESOLVOBJS) $(SUNWOBJS)

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

# CC -v complains about things we aren't going to change in the ISC code
CCVERBOSE=

SRCDIR =	../common
SRCS=		$(BSDOBJS:%.o=../common/bsd/%.c) \
		$(DSTOBJS:%.o=../common/dst/%.c) \
		$(INETOBJS:%.o=../common/inet/%.c) \
		$(IRSOBJS:%.o=../common/irs/%.c) \
		$(ISCOBJS:%.o=../common/isc/%.c) \
		$(NAMESEROBJS:%.o=../common/nameser/%.c) \
		$(RESOLVOBJS:%.o=../common/resolv/%.c) \
		$(SUNWOBJS:%.o=../common/sunw/%.c)

LIBS =		$(DYNLIB) $(LINTLIB)

$(LINTLIB):= 	SRCS = ../common/llib-lresolv

# Local Libresolv definitions

SOLCOMPAT =	-Dsocket=_socket
CRYPTFLAGS=	-DHMAC_MD5 -DUSE_MD5

LOCFLAGS +=	$(CRYPTFLAGS)
LOCFLAGS +=	-D_SYS_STREAM_H -D_REENTRANT -DSVR4 -DSUNW_OPTIONS \
		$(SOLCOMPAT) -I../include -I../../common/inc

CPPFLAGS +=	$(LOCFLAGS) 

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration

DYNFLAGS +=	$(ZNODELETE)

LDLIBS +=	-lsocket -lnsl -lc -lmd

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

# include library targets
include ../../Makefile.targ

pics/%.o: ../common/bsd/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/dst/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/inet/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/irs/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/isc/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/nameser/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/resolv/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/sunw/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

# install rule for lint library target
$(ROOTLINTDIR)/%:	../common/%
	$(INS.file)
