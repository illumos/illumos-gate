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
#ident	"%Z%%M%	%I%	%E% SMI"
#

PROG =		idmapd
MANIFEST =	idmap.xml
SERVEROBJS =	idmapd.o init.o dbutils.o rpc_svc.o server.o adutils.o addisc.o\
	idmap_config.o nldaputils.o
SERVERSRCS =	$(SERVEROBJS:%.o=%.c)
OBJS =		$(SERVEROBJS)
SRCS =		$(SERVERSRCS)
POFILES =	$(OBJS:%.o=%.po)

all :=		TARGET = all
install :=	TARGET = install
clean :=	TARGET = clean
clobber :=	TARGET = clobber

LIBSQLITE =	$(ROOT)/usr/lib/libsqlite.o
SQLITELINT =	$(ROOT)/usr/lib/llib-lsqlite.ln

IDMAP_PROT_DIR =        $(SRC)/head/rpcsvc
IDMAP_PROT_X =          $(IDMAP_PROT_DIR)/idmap_prot.x
IDMAP_PROT_H =          $(IDMAP_PROT_DIR)/idmap_prot.h

include ../../Makefile.cmd

POFILE =	$(PROG)_all.po

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)
$(ROOTMANIFEST) := FILEMODE= 444

INCS += -I. -I../../../lib/libidmap/common -I$(IDMAP_PROT_DIR)

$(OBJS) := CPPFLAGS += $(INCS) -D_REENTRANT
$(POFILE) := CPPFLAGS += $(INCS)
CLOBBERFILES += $(IDMAP_PROT_H)

CFLAGS += -v
LDLIBS += -lsecdb -lresolv -lsocket -lnsl -lidmap -lscf -lldap -luuid

$(PROG) := MAPFILES = $(MAPFILE.INT) $(MAPFILE.NGB)
$(PROG) := LDFLAGS += $(MAPFILES:%=-M%)

DIRMODE = 0755
FILEMODE = 0555
OWNER = root
GROUP = sys

lint_SRCS := CPPFLAGS += $(INCS) -D_REENTRANT
lint := LDLIBS += $(SQLITELINT)

LINTFLAGS += -erroff=E_CONSTANT_CONDITION

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG)

$(IDMAP_PROT_H):	$(IDMAP_PROT_X)
	$(RM) $@; $(RPCGEN) -CMNh -o $@ $(IDMAP_PROT_X)

$(PROG): $(IDMAP_PROT_H) $(OBJS) $$(MAPFILES)
	$(LINK.c) -o $@ $(OBJS) $(LIBSQLITE) $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $(POFILE)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTLIBPROG) $(ROOTMANIFEST)

check: $(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

clobber:

lint:   lint_SRCS

lint_SRCS:

include ../../Makefile.targ

FRC:

