#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#cmd/ipf/lib/Makefile.com
#

LIBRARY=	libipf.a
VERS= .1

OBJECTS=	addicmp.o addipopt.o bcopywrap.o \
		binprint.o buildopts.o checkrev.o count6bits.o \
		count4bits.o debug.o extras.o facpri.o flags.o \
		fill6bits.o genmask.o gethost.o getifname.o \
		getline.o getnattype.o getport.o getportproto.o \
		getproto.o getsumd.o hostmask.o hostname.o \
		hostnum.o icmpcode.o inet_addr.o initparse.o \
		ionames.o ipoptsec.o ipft_ef.o ipft_hx.o \
		ipft_pc.o ipft_sn.o ipft_td.o ipft_tx.o kmem.o \
		kmemcpywrap.o kvatoname.o load_hash.o load_pool.o \
 		load_hashnode.o load_poolnode.o loglevel.o \
		mutex_emul.o nametokva.o natparse.o ntomask.o \
		optname.o optprint.o optvalue.o \
		portname.o portnum.o ports.o print_toif.o \
		printaps.o printbuf.o printhash.o printhashnode.o \
		printip.o printpool.o printpoolnode.o printfr.o \
		printhostmap.o printifname.o printhostmask.o \
		printlog.o printmask.o printnat.o printportcmp.o \
		printpacket.o printpacket6.o printsbuf.o \
		printstate.o ratoi.o \
		remove_pool.o remove_poolnode.o remove_hash.o \
		remove_hashnode.o resetlexer.o rwlock_emul.o \
		tcpflags.o to_interface.o var.o verbose.o \
		v6optvalue.o

include $(SRC)/lib/Makefile.lib
include ../../Makefile.ipf

SRCDIR= ../common
SRCS=	$(OBJECTS:%.o=../common/%.c)

LIBS=		$(LIBRARY)

CPPFLAGS	+= -I../../tools

.KEEP_STATE:

all:    $(LIBS)

lint:	lintcheck

include $(SRC)/lib/Makefile.targ
