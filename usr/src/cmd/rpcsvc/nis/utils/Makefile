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
# cmd/rpcsvc/nis/utils/Makefile
#
# Makefile for the nis_plus utility programs.
#

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint

SUBDIRS= nisaddcred

# links to nischmod
LPROG=	nischgrp  nischown   nischttl

PROG=	niscat    nismatch   nistest    nisdefaults nischmod    nisrm      \
        nisgrep   nismkdir   nisrmdir   nistbladm   nisgrpadm   nisln      \
        nisls     niserror   nispath	nisprefadm

SRCS=	niscat.c  nismatch.c nistest.c  nisdefaults.c nischmod.c  nisrm.c    \
	nisgrep.c nismkdir.c nisrmdir.c nistbladm.c   nisgrpadm.c nisln.c    \
        nisls.c   niserror.c nispath.c	nisprefadm.c

OBJS=	niscat.o  nismatch.o nistest.o  nisdefaults.o nischmod.o  nisrm.o    \
	nisgrep.o nismkdir.o nisrmdir.o nistbladm.o   nisgrpadm.o nisln.o    \
        nisls.o   niserror.o nispath.o	nisprefadm.o

RPROG=  nisaddent nisauthconf
RSRCS=  nisaddent.c nisauthconf.c
ROBJS=  nisaddent.o nisauthconf.o

UTILSRCS= nis_util.c
UTILOBJS= nis_util.o

BACKUP_PROG=	nisbackup
BACKUP_SRCS=	nisbackup.cc ../rpc.nisd/nis_log_common.c \
		../rpc.nisd/nis_mt.c ../rpc.nisd/nis_cleanup.c
BACKUP_OBJS=	nisbackup.o nis_log_common.o nis_mt.o nis_cleanup.o

RESTORE_PROG=	nisrestore
RESTORE_SRCS=	nisrestore.cc ../rpc.nisd/nis_log_common.c \
		../rpc.nisd/nis_mt.c ../rpc.nisd/nis_cleanup.c
RESTORE_OBJS=	nisrestore.o nis_log_common.o nis_mt.o nis_cleanup.o

BKRSTPROG=	$(BACKUP_PROG) $(RESTORE_PROG)

DERIVED_FILES=	../rpc.nisd/nis_svc.h

include ../../../Makefile.cmd

ROOTNSLIB=	$(ROOT)/usr/lib/nis
ROOTUSRSBIN=	$(ROOT)/usr/sbin
ROOTNSPROG=	$(RPROG:%=$(ROOTNSLIB)/%)
ROOTLPROG=	$(LPROG:%=$(ROOTBIN)/%)
ROOTUSBPROG=	$(BKRSTPROG:%=$(ROOTUSRSBIN)/%)
CLOBBERFILES +=	$(RPROG) $(LPROG) $(BACKUP_PROG) $(RESTORE_PROG)\
		$(DERIVED_FILES)

PROTOCOL_DIR=	$(ROOT)/usr/include/rpcsvc
CPPFLAGS += -I$(SRC)/lib/libnsl/include -I$(SRC)/lib/libnisdb
LDLIBS += -lnsl util.a
nispasswd := LDLIBS = $(LDLIBS.cmd) -lnsl

nisbackup := LDFLAGS += $(MAPFILE.INT:%=-M%)
nisrestore := LDFLAGS += $(MAPFILE.INT:%=-M%)

LDLIBS += -lc

.KEEP_STATE:

all: $(DERIVED_FILES) util.a $(SUBDIRS) $(PROG) $(RPROG) $(LPROG) \
	$(BKRSTPROG)

install: all $(SUBDIRS) $(ROOTPROG) $(ROOTNSPROG) $(ROOTLPROG) $(ROOTUSBPROG)

clean:
	$(RM) $(OBJS) $(ROBJS) $(UTILOBJS) $(BACKUP_OBJS) $(RESTORE_OBJS) util.a

lint: lint_SRCS

nispasswd:
	@$(ECHO) "\`\`nispasswd'' is now a link to \`\`passwd''."

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

#
# build an archive library so that those programs that need stuff can
# get it, but others won't link in unneeded routines.
#

util.a: $(UTILOBJS)
	$(AR) -crv $@ $(UTILOBJS)

$(PROG:%=%): $$@.o util.a
	$(LINK.c) -o $@ $@.o $(LDLIBS)
	$(POST_PROCESS)

$(LPROG): nischmod
	-$(RM) $@ ; $(LN) nischmod $@

$(ROOTLPROG): $(ROOTBIN)/nischmod
	-$(RM) $@ ; $(LN) $(ROOTBIN)/nischmod $@

$(ROOTNSLIB):
	$(INS.dir)

$(ROOTNSLIB)/%: % $(ROOTNSLIB)
	$(INS.file)

$(RESTORE_PROG): $(DERIVED_FILES) $(RESTORE_OBJS) util.a $(MAPFILE.INT)
	$(LINK.cc) -o $@ $(RESTORE_OBJS) $(LDLIBS) -lnisdb
	$(POST_PROCESS)

$(BACKUP_PROG): $(DERIVED_FILES) $(BACKUP_OBJS) util.a $(MAPFILE.INT)
	$(LINK.cc) -o $@ $(BACKUP_OBJS) $(LDLIBS) -lnisdb
	$(POST_PROCESS)

nis_log_common.o: ../rpc.nisd/nis_log_common.c $(DERIVED_FILES)
	$(COMPILE.c) ../rpc.nisd/nis_log_common.c
	$(POST_PROCESS_O)

nis_mt.o: ../rpc.nisd/nis_mt.c $(DERIVED_FILES)
	$(COMPILE.c) ../rpc.nisd/nis_mt.c
	$(POST_PROCESS_O)

nis_cleanup.o: ../rpc.nisd/nis_cleanup.c $(DERIVED_FILES)
	$(COMPILE.c) ../rpc.nisd/nis_cleanup.c
	$(POST_PROCESS_O)

#
# Rules for building the derived files :
#
$(DERIVED_FILES): $(PROTOCOL_DIR)/nis.x $(PROTOCOL_DIR)/nis_object.x
	$(RPCGEN) -C -h $(PROTOCOL_DIR)/nis.x |\
	sed -n -e '/EDIT_START/,$$ p' |\
	sed -e 's/_2_svc/_svc/' |\
	sed -e 's/_3_svc/_svc/' |\
	sed -e 's/_3/_clnt/' |\
	sed -e 's/_2/_clnt/' >../rpc.nisd/nis_svc.h

include ../../../Makefile.targ

FRC:
