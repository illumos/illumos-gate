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
# Copyright (c) 2018, Joyent, Inc.

PROTOCOL_DIR= $(ROOT)/usr/include/rpcsvc

BINPROG= rusers rup
SBINPROG= rwall spray
RPROG= rpc.rusersd
SPROG= rpc.sprayd
WPROG= rpc.rwalld
TPROG= rpc.rstatd

PROG= $(BINPROG) $(SBINPROG) $(RPROG) $(SPROG) $(WPROG) $(TPROG)

MANIFEST= \
	rusers.xml \
	spray.xml \
	wall.xml \
	rstat.xml

SVCMETHOD=

SCLNTOBJS= spray.o spray_clnt.o
SSVCOBJS= spray_subr.o spray_svc.o
WCLNTOBJS = rwall.o rwall_clnt.o
WSVCOBJS= rwall_subr.o rwall_svc.o
TSVCOBJS= rstat_main.o rstat_proc.o rstat_svc.o rstat_v2_svc.o rstat_v2_xdr.o

DERIVED_FILES = rstat.x rstat.h rstat_svc.c rstat_v2.h rstat_v2_svc.c \
		rstat_v2_xdr.c spray.x spray.h spray_clnt.c spray_svc.c \
		rwall.x rwall.h rwall_svc.c rwall_clnt.c

include ../Makefile.cmd

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKRPC)

CPPFLAGS= -I. $(CPPFLAGS.master)
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-extra
CERRWARN += -_gcc=-Wno-unused-function

# not linted
SMATCH=off

LDLIBS += -lnsl
rusers :=	CFLAGS += $(CCVERBOSE)
$(BINPROG) :=	LDLIBS += -lrpcsvc
$(RPROG) :=	LDLIBS += -lrpcsvc
$(SPROG) :=	LDLIBS += -lrpcsvc
$(TPROG) :=	LDLIBS += -lrpcsvc
spray :=	LDLIBS += -lrpcsvc


SUBDIRS= rpc.bootparamd
OBJS= $(SCLNTOBJS) $(SSVCOBJS) $(WCLNTOBJS) $(WSVCOBJS) $(TSVCOBJS)
SRCS= $(OBJS:%.o=%.c) rusers.c rpc.rusersd.c rup.c

ETCFILES= rpc

TXTS= $(ETCFILES:%=net_files/%)

NETSVC=	$(ROOTLIB)/netsvc
NIS = $(NETSVC)/nis
RWALL= $(NETSVC)/rwall
RUSERS= $(NETSVC)/rusers
SPRAY= $(NETSVC)/spray
RSTAT= $(NETSVC)/rstat

ROOTDIRS= \
		$(NETSVC) \
		$(NIS) \
		$(RWALL) \
		$(RUSERS) \
		$(SPRAY) \
		$(RSTAT)

IBINPROG=		$(BINPROG:%=$(ROOTBIN)/%)
ISBINPROG=		$(SBINPROG:%=$(ROOTUSRSBIN)/%)
IWPROG=			$(WPROG:%=$(RWALL)/%)
ISPROG=			$(SPROG:%=$(SPRAY)/%)
IRPROG=			$(RPROG:%=$(RUSERS)/%)
ITPROG=			$(TPROG:%=$(RSTAT)/%)
IETCFILES=		$(ETCFILES:%=$(ROOTETC)/%)

# non-default file attributes
$(ROOTETC)/rpc :=				FILEMODE=	0644

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint

rpc.rstatd:=	LDLIBS += -lkstat
rwall:=		CPPFLAGS += -D_REENTRANT
rpc.rwalld:=	CPPFLAGS += -D_REENTRANT

# install rules

$(RWALL)/% $(SPRAY)/% $(RUSERS)/% $(RSTAT)/%: %
	$(INS.file)

$(ROOTETC)/%: ./net_files/%
	$(INS.file)

.KEEP_STATE:

all: $(PROG) $(TXTS) $(SUBDIRS)

# multi-object targets
#
spray:	$(SCLNTOBJS)
	$(LINK.c) $(SCLNTOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

spray_svc.o spray_clnt.o: spray.h

rpc.sprayd: $(SSVCOBJS)
	$(LINK.c) $(SSVCOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

rwall_svc.o rwall_clnt.o: rwall.h

rwall: $(WCLNTOBJS)
	$(LINK.c) $(WCLNTOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

rpc.rwalld: $(WSVCOBJS)
	$(LINK.c) $(WSVCOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

rstat_main.o:	rstat.h rstat_v2.h

rstat_svc.o: rstat.h

rstat_V2_svc.o rstat_V2_xdr.o: rstat_v2.h

rpc.rstatd: $(TSVCOBJS)
	$(LINK.c) $(TSVCOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: $(PROG) $(TXTS) .WAIT $(ROOTDIRS) .WAIT $(IBINPROG) $(ISBINPROG) \
	$(IWPROG) $(ISPROG) $(IRPROG) $(ITPROG) $(IETCFILES) $(SUBDIRS) \
	$(ROOTMANIFEST) $(ROOTSVCMETHOD)

$(ROOTDIRS):
	$(INS.dir)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

#
# Derived files
#

rstat.x: $(PROTOCOL_DIR)/rstat.x
	$(RM) rstat.x
	$(CP) $(PROTOCOL_DIR)/rstat.x rstat.x

rstat.h: $(PROTOCOL_DIR)/rstat.h
	$(RM) rstat.h
	$(CP) $(PROTOCOL_DIR)/rstat.h rstat.h

rstat_svc.c: rstat.x
	$(RPCGEN) -C -m rstat.x > $@

rstat_v2.h: rstat_v2.x
	$(RPCGEN) -C -h rstat_v2.x > $@

rstat_v2_svc.c: rstat_v2.x
	$(RPCGEN) -C -m rstat_v2.x > $@

rstat_v2_xdr.c: rstat_v2.x
	$(RPCGEN) -c rstat_v2.x > $@

spray.x: $(PROTOCOL_DIR)/spray.x
	$(RM) spray.x
	$(CP) $(PROTOCOL_DIR)/spray.x spray.x

spray.h: $(PROTOCOL_DIR)/spray.h
	$(RM) spray.h
	$(CP) $(PROTOCOL_DIR)/spray.h spray.h

spray_svc.c: spray.x
	$(RPCGEN) -s datagram_v -s circuit_v spray.x > $@

spray_clnt.c: spray.x
	$(RPCGEN) -l spray.x > $@

rwall.x: $(PROTOCOL_DIR)/rwall.x
	$(RM) rwall.x
	$(CP) $(PROTOCOL_DIR)/rwall.x rwall.x

rwall.h: $(PROTOCOL_DIR)/rwall.h
	$(RM) rwall.h
	$(CP) $(PROTOCOL_DIR)/rwall.h rwall.h

rwall_svc.c: rwall.x
	$(RPCGEN) -A -s datagram_v rwall.x > $@

rwall_clnt.c: rwall.x
	$(RPCGEN) -l -M rwall.x > $@

check:	$(CHKMANIFEST)

clean: $(SUBDIRS)
	-$(RM) $(OBJS) $(DERIVED_FILES)

clobber: $(SUBDIRS)

lint:
	$(LINT.c) $(WCLNTOBJS:%.o=%.c) -lnsl -lrpcsvc
	$(LINT.c) $(WSVCOBJS:%.o=%.c) -lnsl -lrpcsvc
	$(LINT.c) rusers.c -lnsl -lrpcsvc

FRC:

include ../Makefile.targ
