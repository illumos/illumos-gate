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

LIBRARY= libresolv.a
VERS= .2

BSDOBJS=   	daemon.o	putenv.o	strcasecmp.o	strsep.o \
		ftruncate.o	readv.o		strdup.o	strtoul.o \
		gettimeofday.o	setenv.o	strerror.o	utimes.o \
		mktemp.o	setitimer.o	strpbrk.o	writev.o

DSTOBJS=	dst_api.o	prandom.o	support.o

DSTLINKOBJS=	bsafe_link.o	cylink_link.o	eay_dss_link.o	hmac_link.o \
		rsaref_link.o

INETOBJS=	inet_net_pton.o	inet_ntop.o	\
		inet_neta.o	inet_pton.o	inet_lnaof.o	inet_netof.o \
		nsap_addr.o	inet_makeaddr.o	inet_network.o \
		inet_net_ntop.o	inet_ntoa.o	inet_cidr_ntop.o \
		inet_cidr_pton.o		inet_data.o

IRSOBJS=	dns.o		gen_ho.o	getnetgrent.o	lcl_ng.o \
		nis_nw.o	dns_gr.o	gen_ng.o	getprotoent.o \
		lcl_nw.o	nis_pr.o	dns_ho.o	gen_nw.o \
		getpwent.o	lcl_pr.o	nis_pw.o	dns_nw.o \
		gen_pr.o	getservent.o	lcl_pw.o	nis_sv.o \
		dns_pr.o	gen_pw.o	hesiod.o	lcl_sv.o \
		nul_ng.o	dns_pw.o	gen_sv.o	irs_data.o \
		nis.o		util.o		dns_sv.o	getgrent.o \
		lcl.o		nis_gr.o	gen.o		gethostent.o \
		lcl_gr.o	nis_ho.o	gen_gr.o	getnetent.o \
		lcl_ho.o	nis_ng.o	getpwent_r.o \
		getservent_r.o	gai_strerror.o	getgrent_r.o \
		gethostent_r.o	getnetent_r.o	getnetgrent_r.o \
		getprotoent_r.o	getnameinfo.o	irp.o		irpmarshall.o \
		irp_ho.o	irp_nw.o	irp_pr.o	irp_sv.o \
		irp_gr.o	irp_ng.o	irp_pw.o

IRSRESOBJS=	dns.o		gen_ho.o	lcl_ng.o	dns_gr.o \
		gen_ng.o	lcl_nw.o	dns_ho.o	gen_nw.o \
		lcl_pr.o	dns_nw.o	gen_pr.o	lcl_pw.o \
		dns_pr.o	gen_pw.o	hesiod.o	lcl_sv.o \
		nul_ng.o	dns_pw.o	gen_sv.o	irs_data.o \
		util.o		dns_sv.o	lcl.o		gen.o \
		gethostent.o	lcl_gr.o	gen_gr.o	lcl_ho.o \
		gethostent_r.o	getaddrinfo.o

IRSDYNOBJS=	nis_nw.o	nis_pr.o	nis_pw.o	nis_sv.o \
		nis.o		nis_gr.o	nis_ho.o	nis_ng.o \
		irp.o		irpmarshall.o	irp_ho.o	irp_nw.o \
		irp_pr.o	irp_sv.o	irp_gr.o	irp_ng.o \
		irp_pw.o	getnetent.o	getpwent_r.o	getgrent_r.o \
		getservent_r.o	getnetent_r.o	getnetgrent_r.o	getgrent.o \
		getnetgrent.o	getprotoent.o	getpwent.o	getservent.o \
		getprotoent_r.o	getnameinfo.o	gai_strerror.o

ISCOBJS=	base64.o	ev_files.o	ev_waits.o	logging.o \
		bitncmp.o	ev_streams.o	eventlib.o	tree.o \
		ev_connects.o	ev_timers.o	heap.o		assertions.o \
		memcluster.o	ctl_p.o		ctl_clnt.o	ctl_srvr.o \
		hex.o

NAMESEROBJS=	ns_name.o	ns_netint.o	ns_parse.o	ns_print.o \
		ns_ttl.o	ns_sign.o	ns_verify.o	ns_date.o \
		ns_samedomain.o

RESOLVOBJS=	herror.o	res_debug.o	res_data.o	res_comp.o \
		res_init.o	res_mkquery.o	res_mkupdate.o	res_query.o \
		res_send.o	res_update.o	res_sendsigned.o \
		res_findzonecut.o

SUNWOBJS=	sunw_mtctxres.o	sunw_dst_init.o	sunw_irs_init.o	sunw_updrec.o

OBJECTS=	$(BSDOBJS) $(DSTOBJS) $(INETOBJS) $(IRSRESOBJS) $(ISCOBJS) \
		$(NAMESEROBJS) $(RESOLVOBJS) $(SUNWOBJS)

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

SRCDIR =	../common
SRCS=		$(BSDOBJS:%.o=../common/bsd/%.c) \
		$(DSTOBJS:%.o=../common/dst/%.c) \
		$(INETOBJS:%.o=../common/inet/%.c) \
		$(IRSRESOBJS:%.o=../common/irs/%.c) \
		$(ISCOBJS:%.o=../common/isc/%.c) \
		$(NAMESEROBJS:%.o=../common/nameser/%.c) \
		$(RESOLVOBJS:%.o=../common/resolv/%.c) \
		$(SUNWOBJS:%.o=../common/sunw/%.c)

LIBS =		$(DYNLIB) $(LINTLIB)

$(LINTLIB):= 	SRCS = ../common/llib-lresolv

# Local Libresolv definitions
SOLCOMPAT =	-Dgethostbyname=res_gethostbyname \
	-Dgethostbyaddr=res_gethostbyaddr -Dgetnetbyname=res_getnetbyname \
	-Dgethostbyname2=res_gethostbyname2\
	-Dgetnetbyaddr=res_getnetbyaddr -Dsethostent=res_sethostent \
	-Dendhostent=res_endhostent -Dgethostent=res_gethostent \
	-Dsetnetent=res_setnetent -Dendnetent=res_endnetent \
	-Dgetnetent=res_getnetent -Dsocket=_socket \
	-Dgetipnodebyname=res_getipnodebyname \
	-Dgetipnodebyaddr=res_getipnodebyaddr \
	-Dfreehostent=res_freehostent \
	-Dgetaddrinfo=res_getaddrinfo \
	-Dfreeaddrinfo=res_freeaddrinfo

CRYPTFLAGS=	-DCYLINK_DSS -DHMAC_MD5 -DUSE_MD5 -DDNSSAFE

LOCFLAGS +=	$(CRYPTFLAGS)
LOCFLAGS +=	-D_SYS_STREAM_H -D_REENTRANT -DSVR4 -DSUNW_OPTIONS \
		$(SOLCOMPAT) -I../include -I../../common/inc

CPPFLAGS +=	$(LOCFLAGS) 
DYNFLAGS +=	$(ZNODELETE)
LDLIBS +=	-lsocket -lnsl -lc

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
