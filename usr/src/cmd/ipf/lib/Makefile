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

LIBRARY=	libipf.a
VERS= .1

OBJECTS=	addicmp.o addipopt.o bcopywrap.o \
		binprint.o buildopts.o checkrev.o count6bits.o \
		count4bits.o debug.o extras.o facpri.o flags.o \
		fill6bits.o genmask.o gethost.o getifname.o \
		getline.o getnattype.o getport.o getportproto.o \
		getproto.o getsumd.o hostname.o \
		icmpcode.o inet_addr.o initparse.o \
		ionames.o v6ionames.o ipoptsec.o ipf_dotuning.o \
		ipft_ef.o ipft_hx.o ipft_pc.o ipft_sn.o ipft_td.o \
		ipft_tx.o kmem.o kmemcpywrap.o kvatoname.o \
		load_hash.o load_pool.o load_hashnode.o \
		load_poolnode.o loglevel.o mutex_emul.o nametokva.o \
		nat_setgroupmap.o ntomask.o optname.o optprint.o \
		optprintv6.o optvalue.o \
		portname.o portnum.o ports.o print_toif.o \
		printactivenat.o printaps.o printbuf.o printhash.o \
		printhashnode.o printip.o printpool.o \
		printpoolnode.o printfr.o printfraginfo.o \
		printhostmap.o printifname.o printhostmask.o \
		printlog.o printlookup.o printmask.o printnat.o printpacket.o \
		printpacket6.o printportcmp.o printproto.o \
		printsbuf.o printstate.o printtunable.o ratoi.o \
		remove_pool.o remove_poolnode.o remove_hash.o \
		remove_hashnode.o resetlexer.o rwlock_emul.o \
		tcpflags.o var.o verbose.o \
		v6ionames.o v6optvalue.o printpool_live.o \
		printpooldata.o printhash_live.o printhashdata.o \
		printactiveaddr.o printactivenat.o printaddr.o

include $(SRC)/lib/Makefile.lib
include $(SRC)/lib/Makefile.lib.64
include ../Makefile.ipf

LIBS=		$(LIBRARY)

CPPFLAGS	+= -I../tools

.KEEP_STATE:

all:    $(LIBS)

install: all

include $(SRC)/lib/Makefile.targ
