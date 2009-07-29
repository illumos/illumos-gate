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

PROG =		idmapd
MANIFEST =	idmap.xml
SERVEROBJS =				\
	directory_provider_builtin.o	\
	directory_provider_nsswitch.o	\
	directory_provider_ad.o		\
	directory_server.o		\
	adutils.o			\
	dbutils.o			\
	idmap_config.o			\
	idmapd.o			\
	init.o				\
	nldaputils.o			\
	rpc_svc.o			\
	server.o			\
	wksids.o

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

include ../../Makefile.cmd

TEXT_DOMAIN =	SUNW_OST_OSLIB
XGETTEXT =	$(GNUXGETTEXT)
XGETFLAGS =	--foreign-user --strict -n -E --width=72 \
		--omit-header --keyword=directoryError:2 \
		--language=C --force-po

C99MODE = $(C99_ENABLE)
POFILE =	$(PROG)_all.po

RPC_MSGOUT_OPT = -DRPC_MSGOUT=idmap_rpc_msgout

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)
$(ROOTMANIFEST) := FILEMODE= 444

INCS += -I. -I../../../lib/libidmap/common\
	 -I../../../lib/libsldap/common\
	 -I../../../lib/libadutils/common

$(OBJS) := CPPFLAGS += $(INCS) -D_REENTRANT
$(POFILE) := CPPFLAGS += $(INCS)

CFLAGS += -v
LDLIBS += -lsecdb \
	-lsocket \
	-lnsl \
	-lidmap \
	-lscf \
	-lsldap \
	-lldap \
	-luuid \
	-ladutils \
	-lumem

rpc_svc.o := CFLAGS += $(RPC_MSGOUT_OPT)

$(PROG) := MAPFILES = $(MAPFILE.INT) $(MAPFILE.NGB)
$(PROG) := LDFLAGS += $(MAPFILES:%=-M%)

DIRMODE = 0755
FILEMODE = 0555

lint_SRCS := CPPFLAGS += $(INCS) -D_REENTRANT $(RPC_MSGOUT_OPT)
lint := LDLIBS += $(SQLITELINT)

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG)

$(PROG): $(OBJS) $$(MAPFILES)
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

