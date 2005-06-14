#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/cmd-inet/Makefile.cmd-inet

PROG= mipagent

LCLOBJS=aaa.o \
	agent.o	\
	agentID.o \
	agentInit.o \
	agentKernelIntfce.o	\
	agentNet.o \
	agentPeriodic.o \
	agentSaveState.o \
	auth.o \
	utils.o \
	snmp_tree.o \
	snmp_stub.o \
	snmp_trap.o \
	snmp_appl.o \
	snmp_faCOAEntry.o \
	snmp_faVisitorEntry.o \
	snmp_haCounterEntry.o \
	snmp_haMobilityBindingEntry.o \
	snmp_maAdvConfigEntry.o	\
	snmp_mipSecAssocEntry.o \
	snmp_mipSecViolationEntry.o \
	mipagentstat_server.o \
	pool.o \
	hash.o \
	thq.o \
	setup.o

COMOBJS= conflib.o

OBJS= $(LCLOBJS) $(COMOBJS)

HDRS=	aaa.h \
	agent.h \
	agentKernelIntfce.h	\
	auth.h \
	hash.h \
	mip.h \
	snmp_stub.h \
	pool.h \
	setup.h \
	thq.h

# Auxiliary files for the SNMP subagent
SNMP_FILES=	mipagent.acl mipagent.reg
SNMP_CONF_DIR=	$(ROOT)/etc/snmp/conf
INS_SNMP_FILES=	$(SNMP_FILES:%=$(SNMP_CONF_DIR)/%)
$(SNMP_CONF_DIR)/mipagent.acl:=	FILEMODE= 600
$(SNMP_CONF_DIR)/mipagent.reg:=	FILEMODE= 644
$(INS_SNMP_FILES):=		OWNER= root
$(INS_SNMP_FILES):=		GROUP= sys
$(SNMP_CONF_DIR):=		OWNER= root
$(SNMP_CONF_DIR):=		GROUP= sys

SRCS=	$(LCLOBJS:%.o=%.c) $(COMOBJS:%.o=$(CMDINETCOMMONDIR)/%.c)

SNMPINC = -I$(SRC)/cmd/agents/snmp/snmplib -I$(SRC)/cmd/agents/snmp/agent

LDLIBS += -lxnet -lnsl -lsocket -lssagent -lmd5
CPPFLAGS += -DMIP_DEBUG -I$(CMDINETCOMMONDIR) $(SNMPINC) -DNO_SIMULTANEOUS \
	    -DINI -D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT

# mipagent uses the ancillary data feature which is available
# only through UNIX 98 standards version of Socket interface.
# these #defines are required to use UNIX 98 interfaces
CPPFLAGS += -D_XOPEN_SOURCE=500 -D__EXTENSIONS__

#
# Note that we include KEY_DISTRIBUTION in LINTFLAGS because otherwise
# lint thinks aaaCreateKey() can be static, which is really not right.
#
LINTFLAGS += -DKEY_DISTRIBUTION

#
# Turn off some of lint's argument checking to workaround the fact
# that we use both libsocket *and* libxnet interfaces (whose prototypes
# don't always agree).
#
LINTFLAGS += -erroff=E_INCONS_ARG_DECL2 -erroff=E_INCONS_ARG_USED2 \
		-erroff=E_INCONS_VAL_TYPE_DECL2

#
# We turn off these errors work around brokenness in the snmp interfaces
# (specifically: they require us to define and export data for their
# use, which lint has no clue about).
#
LINTFLAGS += -erroff=E_NAME_DEF_NOT_USED2 -erroff=E_GLOBAL_COULD_BE_STATIC2

.KEEP_STATE:

.PARALLEL: $(OBJS) $(INS_SNMP_FILES)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

include ../Makefile.lib

install: all $(ROOTLIBINETPROG) $(SNMP_CONF_DIR) .WAIT $(INS_SNMP_FILES)

$(SNMP_CONF_DIR):
	$(INS.dir)

$(SNMP_CONF_DIR)/%: %
	$(INS.file)

clean:
	$(RM) $(OBJS)

check: $(HDRS:%.h=%.check) $(SRCS:%.c=%.check)

%.check: %.c
	$(DOT_C_CHECK)

lint: lint_SRCS

include $(SRC)/cmd/Makefile.targ
