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
# Makefile for the nis+ daemon
#

INIT_OBJS= nisinit.o 

LOG_OBJS= nislog.o nis_log_common.o nis_mt.o nis_cleanup.o

NISLDAPMAPTEST_OBJS=	nisldapmaptest.o

SRV_OBJS= \
  nis_main.o     nis_ns_proc.o     nis_ib_proc.o     nis_xx_proc.o   \
  nis_db.o       nis_subr_proc.o   nis_log_common.o  yp_ns_proc.o    \
  nis_log_svc.o  nis_service.o     resolv_common.o   resolv.o	     \
  ypserv1.o      nis_multival.o	   nis_opacc.o       nis_mt.o        \
  nis_thread_funcs.o               nis_cleanup.o     ldap_log.o

SRCS= \
  nis_main.c      nis_ns_proc.c     nis_ib_proc.c   nis_xx_proc.c   nis_db.c  \
  nis_subr_proc.c nis_log_common.c  yp_ns_proc.c    nisinit.c \
  nis_log_svc.c   nis_service.c     resolv_common.c resolv.c	  ypserv1.c \
  nis_multival.c  nis_opacc.c       nis_mt.c        nis_thread_funcs.c \
  nisldapmaptest.c

OBJS= $(SRV_OBJS) $(INIT_OBJS)
PROG= nisinit rpc.nisd nislog nisldapmaptest

DERIVED_FILES= nis_svc.h
CLEANFILES += $(DERIVED_FILES)

include $(SRC)/cmd/Makefile.cmd

PROTOCOL_DIR= $(ROOT)/usr/include/rpcsvc
CPPFLAGS += -I$(SRC)/lib/libnsl/include -I$(SRC)/lib/libnisdb

nislog :=	LDLIBS += -lnisdb
nislog :=	CCFLAGS += -DNEED_DIROBJ
rpc.nisd :=	CCFLAGS += $(CCMT) -DNEED_DIROBJ
rpc.nisd :=	LDLIBS += -lnisdb -lldap
nisldapmaptest :=	LDLIBS += -lnisdb -lldap
LDLIBS += -lnsl -lc

MAPFILE.INT.L =	$(MAPFILE.NGB) mapfile-intf-nislog
MAPFILE.INT.T =	$(MAPFILE.NGB) mapfile-intf-nisldapmaptest
MAPFILE.INT.R =	$(MAPFILE.NGB) mapfile-intf-rpc.nisd
nislog :=	LDFLAGS += $(MAPFILE.INT.L:%=-M%)
nisldapmaptest :=	LDFLAGS += $(MAPFILE.INT.T:%=-M%)
rpc.nisd :=	LDFLAGS += $(MAPFILE.INT.R:%=-M%)

SUBDIR= resolv_server configs

.KEEP_STATE:

all := TARGET= all
install := TARGET= install
clean := TARGET= clean
clobber := TARGET= clobber
lint := TARGET= lint

all: $(DERIVED_FILES) $(PROG) $(SUBDIR)

install: all $(ROOTUSRSBINPROG) $(SUBDIR)

clean:
	$(RM) $(LOG_OBJS) $(OBJS) $(CLEANFILES)

lint: lint_SRCS

#
# Explicit link rules for the actual programs to get around the C++
# situation.
#
nislog: $(LOG_OBJS) $(MAPFILE.INT.L)
	$(LINK.cc) -o $@ $(LOG_OBJS) $(LDLIBS)
	$(POST_PROCESS)

nisinit: $(INIT_OBJS)
	$(LINK.c) -o $@ $(INIT_OBJS) $(LDLIBS)
	$(POST_PROCESS)

rpc.nisd: $(SRV_OBJS) $(MAPFILE.INT.R)
	$(LINK.cc) -o $@ $(SRV_OBJS) $(LDLIBS)
	$(POST_PROCESS)

nisldapmaptest: $(NISLDAPMAPTEST_OBJS) $(MAPFILE.INT.T)
	$(LINK.cc) -o $@ $(NISLDAPMAPTEST_OBJS) $(LDLIBS)
	$(POST_PROCESS)

nplt: nisldapmaptest

$(SUBDIR): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

SRC_DER=nis_main.o nis_service.o nis_subr_proc.o nis_xx_proc.o nisinit.o
$(SRC_DER): nis_svc.h

FRC:

#
# Rules for building the derived files :
#
nis_svc.h: $(PROTOCOL_DIR)/nis.x $(PROTOCOL_DIR)/nis_object.x
	$(RPCGEN) -C -h $(PROTOCOL_DIR)/nis.x |\
	$(SED) -n -e '/EDIT_START/,$$ p' |\
	$(SED) -e 's/_2_svc/_svc/' |\
	$(SED) -e 's/_3_svc/_svc/' |\
	$(SED) -e 's/_3/_clnt/' |\
	$(SED) -e 's/_2/_clnt/' >nis_svc.h

include $(SRC)/cmd/Makefile.targ
