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

LIBRARY= dnssafe.a
VERS= .1

DSTOBJS= 	bsafe_link.o	hmac_link.o	rsaref_link.o	eay_dss_link.o

DNSSAFEOBJS=	ahcbcpad.o	ahchdig.o	ahchencr.o	ahchgen.o \
		ahchrand.o	ahdigest.o	ahencryp.o	ahgen.o \
		ahrandom.o	ahrsaenc.o	ahrsaepr.o	ahrsaepu.o \
		aichdig.o	aichenc8.o	aichencn.o	aichencr.o \
		aichgen.o	aichrand.o	aimd5.o		aimd5ran.o \
		ainfotyp.o	ainull.o	airsaepr.o	airsaepu.o \
		airsakgn.o	airsaprv.o	airsapub.o	algchoic.o \
		algobj.o	amcrte.o	ammd5.o		ammd5r.o \
		amrkg.o		amrsae.o	balg.o		bgclrbit.o \
		bgmdmpyx.o	bgmdsqx.o	bgmodexp.o	bgpegcd.o \
		big2exp.o	bigabs.o	bigacc.o	bigarith.o \
		bigcmp.o	bigconst.o	biginv.o	biglen.o \
		bigmodx.o	bigmpy.o	bigpdiv.o	bigpmpy.o \
		bigpmpyh.o	bigpmpyl.o	bigpsq.o	bigqrx.o \
		bigsmod.o	bigtocan.o	bigu.o		bigunexp.o \
		binfocsh.o	bkey.o		bmempool.o	cantobig.o \
		crt2.o		digest.o	digrand.o	encrypt.o \
		generate.o	intbits.o	intitem.o	keyobj.o \
		ki8byte.o	kifulprv.o	kiitem.o	kinfotyp.o \
		kipkcrpr.o	kirsacrt.o	kirsapub.o	\
		md5rand.o	prime.o		random.o	rsa.o \
		rsakeygn.o	seccbcd.o	seccbce.o	surrendr.o

OBJECTS=	$(DSTOBJS) $(DNSSAFEOBJS)

include ../../../Makefile.lib

LIBNAME=	$(LIBRARY:%.a=%)
LIBS=		$(DYNLIB)
LDLIBS +=	-lmd -lresolv -lc

MAPFILES =	../mapfile-vers

SRCDIR=		../../common/dnssafe
SRCS=		$(DSTOBJS:%.o=../../common/dst/%.c) \
		$(DNSSAFEOBJS:%.o=$(SRCDIR)/%.c)

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
