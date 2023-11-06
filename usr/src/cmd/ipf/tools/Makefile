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
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#
# Copyright (c) 2012, Joyent Inc. All rights reserved.
#
# cmd/ipf/tools/Makefile
#
#

include ../../Makefile.cmd
include ../../Makefile.cmd.64
include ../Makefile.ipf
include ../../Makefile.ctf

LICENCE= IPFILTER.LICENCE

PROG=		ipf ipfs ipmon ipnat ippool ipfstat
IPFPROG=	ipftest

IPF_OBJS=	ipf.o ipfcomp.o ipfzone.o ipf_y.o ipf_l.o
IPFS_OBJS=	ipfs.o ipfzone.o
IPFSTAT_OBJS=	ipfstat.o ipfzone.o
IPMON_OBJS=	ipmon.o ipfzone.o ipmon_y.o ipmon_l.o
IPNAT_OBJS=	ipnat.o ipfzone.o ipnat_y.o ipnat_l.o
IPPOOL_OBJS=	ippool.o ipfzone.o ippool_y.o ippool_l.o
IPFTEST_OBJS=	cfw.o ipftest.o ipfzone.o \
		ip_fil.o ip_state.o ip_compat.o \
		ip_frag.o ip_nat.o ip_nat6.o fil.o \
		ip_htable.o ip_lookup.o \
		ip_proxy.o ip_auth.o ip_log.o \
		ipf_y.o ipf_l.o \
		ipnat_y.o ipnat_l.o \
		ippool_y.o ippool_l.o \
		ip_pool.o radix.o

USRLIBIPF=		$(ROOTLIB)/ipf
USRLIBIPFLICENCE=	$(LICENCE:%=$(USRLIBIPF)/%)

$(USRLIBIPFLICENCE):=FILEMODE= 0644

CFLAGS += -D_ELF64
LDLIBS += -L ../lib -lipf

LDLIBS		+= $(LIBBPF)
LDFLAGS		+= $(MAPFILE.NGB:%=-Wl,-M%)

CPPFLAGS	+= -I. -DIPFILTER_LOOKUP -DIPFILTER_LOG

ipfstat.o	:=	CPPFLAGS += -DSTATETOP
ipfstat		:=	LDLIBS += -lcurses

ipf		:=	LDLIBS += -lsocket -lnsl -luuid
ipf		:=	OBJS += $(IPF_OBJS)
ipfs		:=	OBJS += $(IPFS_OBJS)
ipftest		:=	LDLIBS += -lsocket -lnsl -lmd -luuid
ipftest		:=	OBJS += $(IPFTEST_OBJS)
ipfstat		:=	LDLIBS += -lsocket -lnsl -lkvm -lelf -luuid
ipfstat		:=	OBJS += $(IPFSTAT_OBJS)
ipmon		:=	LDLIBS += -lsocket -lnsl -luuid
ipmon		:=	OBJS += $(IPMON_OBJS)
ipnat		:=	LDLIBS += -lsocket -lnsl -lkvm -lelf -luuid
ipnat		:=	OBJS += $(IPNAT_OBJS)
ippool		:=	LDLIBS += -lsocket -lnsl -lkvm -lelf -luuid
ippool		:=	OBJS += $(IPPOOL_OBJS)

CLEANFILES	+= $(IPF_OBJS) $(IPFS_OBJS) $(IPFTEST_OBJS) $(IPFSTAT_OBJS)
CLEANFILES	+= $(IPMON_OBJS) $(IPNAT_OBJS) $(IPPOOL_OBJS)
CLOBBERFILES	+= $(IPFPROG)

ROOTIPF=	$(ROOTLIB)/ipf

ROOTIPFPROG=	$(IPFPROG:%=$(ROOTIPF)/%)

.KEEP_STATE:

all: $(PROG) $(IPFPROG)

install: all install_local $(ROOTIPF) $(ROOTUSRSBINPROG) $(ROOTIPFPROG)

$(USRLIBIPF):
	$(INS.dir)

$(USRLIBIPF)/% : %
	$(INS.file)

$(ROOTIPF)/%: %
	$(INS.file)

ipf:	$(IPF_OBJS) $(LIBIPF) $(MAPFILE.NGB)
	$(LINK.c) -o ipf $(IPF_OBJS) $(LDLIBS)
	$(POST_PROCESS)

ipf_y.o: ipf_y.c $(COMMONIPF)/netinet/ip_fil.h $(COMMONIPF)/ipf.h \
	ipf_y.c ipf_l.h

ipf_y.c ipf_y.h: ipf_y.y
	$(YACC) -d -b ipf ipf_y.y
	sed -e 's/yy/ipf_yy/g' -e 's/y.tab.h/ipf_y.c/' \
	   ipf.tab.c > ipf_y.c
	sed -e 's/yy/ipf_yy/g' -e 's/y.tab.h/ipf_y.h/' \
	   ipf.tab.h > ipf_y.h

CLEANFILES += ipf.tab.c ipf.tab.h
CLEANFILES += ipf_y.c ipf_y.h

ipf_l.o: ipf_l.c $(COMMONIPF)/netinet/ip_fil.h $(COMMONIPF)/ipf.h  \
	 ipf_y.h ipf_l.h

ipf_l.c: lexer.c $(COMMONIPF)/ipf.h $(COMMONIPF)/netinet/ip_fil.h
	sed -e 's/yy/ipf_yy/g' -e 's/y.tab.h/ipf_y.h/' \
	       -e 's/lexer.h/ipf_l.h/' lexer.c > $@

ipf_l.h: lexer.h
	sed -e 's/yy/ipf_yy/g' lexer.h > $@

CLEANFILES += ipf_l.c ipf_l.h

ipfs:	$(IPFS_OBJS)
	$(LINK.c) -o ipfs $(IPFS_OBJS) $(LDLIBS)
	$(POST_PROCESS)

ipfstat:	$(IPFSTAT_OBJS) $(MAPFILE.NGB)
	$(LINK.c) -o ipfstat $(IPFSTAT_OBJS) $(LDLIBS)
	$(POST_PROCESS)

ipmon:	$(IPMON_OBJS) $(LIBIPF) $(MAPFILE.NGB)
	$(LINK.c) -o ipmon $(IPMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

ipmon_y.o: ipmon_y.c $(COMMONIPF)/ipmon.h ipmon_y.h ipmon_l.h

ipmon_y.c ipmon_y.h: ipmon_y.y
	$(YACC) -d -b ipmon ipmon_y.y
	sed -e 's/yy/ipmon_yy/g' \
	    -e 's/extern [a-z]* .*();//' \
	    -e 's/^\(static [a-z]* .*\)();/\1(void);/' \
	   ipmon.tab.c > ipmon_y.c
	sed -e 's/yy/ipmon_yy/g' -e 's/y.tab.h/ipmon_y.h/' \
	   ipmon.tab.h > ipmon_y.h

CLEANFILES += ipmon.tab.c ipmon.tab.h
CLEANFILES += ipmon_y.c ipmon_y.h

ipmon_l.o: ipmon_l.c $(COMMONIPF)/ipmon.h ipmon_y.h ipmon_l.h

ipmon_l.c: lexer.c $(COMMONIPF)/ipmon.h
	sed -e 's/yy/ipmon_yy/g' -e 's/y.tab.h/ipmon_y.h/' \
            -e 's/lexer.h/ipmon_l.h/' lexer.c > $@

ipmon_l.h: lexer.h
	sed -e 's/yy/ipmon_yy/g' lexer.h > $@

CLEANFILES += ipmon_l.c ipmon_l.h

ipnat:	$(IPNAT_OBJS) $(LIBIPF) $(MAPFILE.NGB)
	$(LINK.c) -o ipnat $(IPNAT_OBJS) $(LDLIBS)
	$(POST_PROCESS)

ipnat_y.o: ipnat_y.c $(COMMONIPF)/netinet/ip_nat.h ipnat_y.h ipnat_l.h

ipnat_y.c ipnat_y.h: ipnat_y.y
	$(YACC) -d -b ipnat ipnat_y.y
	sed -e 's/yy/ipnat_yy/g' \
	    -e 's/extern [a-z]* .*();//' \
	    -e 's/^\(static [a-z]* .*\)();/\1(void);/' \
	   ipnat.tab.c > ipnat_y.c
	sed -e 's/yy/ipnat_yy/g' -e 's/y.tab.h/ipnat_y.h/' \
	   ipnat.tab.h > ipnat_y.h

CLEANFILES += ipnat.tab.c ipnat.tab.h
CLEANFILES += ipnat_y.c ipnat_y.h

ipnat_l.o: ipnat_l.c $(COMMONIPF)/netinet/ip_nat.h ipnat_l.h

ipnat_l.c: lexer.c $(COMMONIPF)/netinet/ip_nat.h
	sed -e 's/yy/ipnat_yy/g' -e 's/y.tab.h/ipnat_y.h/' \
	       -e 's/lexer.h/ipnat_l.h/' lexer.c > $@

ipnat_l.h: lexer.h
	sed -e 's/yy/ipnat_yy/g' lexer.h > $@

CLEANFILES += ipnat_l.c ipnat_l.h

ippool:	$(IPPOOL_OBJS) $(LIBIPF) $(MAPFILE.NGB)
	$(LINK.c) -o ippool $(IPPOOL_OBJS) $(LDLIBS)
	$(POST_PROCESS)

ippool_y.o: ippool_y.c $(COMMONIPF)/netinet/ip_pool.h ippool_y.h ippool_l.h

ippool_y.c ippool_y.h: ippool_y.y
	$(YACC) -d -b ippool ippool_y.y
	sed -e 's/yy/ippool_yy/g' \
	    -e 's/extern [a-z]* .*();//' \
	    -e 's/^\(static [a-z]* .*\)();/\1(void);/' \
	   ippool.tab.c > ippool_y.c
	sed -e 's/yy/ippool_yy/g' -e 's/y.tab.h/ippool_y.h/' \
	   ippool.tab.h > ippool_y.h

CLEANFILES += ippool.tab.c ippool.tab.h
CLEANFILES += ippool_y.c ippool_y.h

ippool_l.o: ippool_l.c $(COMMONIPF)/netinet/ip_pool.h ippool_l.h

ippool_l.c: lexer.c $(COMMONIPF)/netinet/ip_pool.h
	sed -e 's/yy/ippool_yy/g' -e 's/y.tab.h/ippool_y.h/' \
	       -e 's/lexer.h/ippool_l.h/' lexer.c > $@

ippool_l.h: lexer.h
	sed -e 's/yy/ippool_yy/g' lexer.h > $@

CLEANFILES += ippool_l.c ippool_l.h

ipftest:	$(IPFTEST_OBJS) $(LIBIPF) $(MAPFILE.NGB)
	$(LINK.c) $(ZIGNORE) -o ipftest $(IPFTEST_OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	-$(RM) $(CLEANFILES)

#
# NOTE: all rules must use relative paths otherwise absolute paths will be
#       embedded into the binaries making them false positives and
#       reported by wsdiff
#

%.o:	../../../uts/common/inet/ipf/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o:	../../../common/net/patricia/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

install_local: $(USRLIBIPF) $(USRLIBIPFLICENCE)

include ../../Makefile.targ
