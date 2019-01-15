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

COMMONBASE = ../../common


PROG = fcinfo
ROOT_PROG_LINK = $(ROOTUSRSBIN)/fcadm
MANIFEST = npiv_config.xml
SVCMETHOD = npivconfig
PRODUCT = $(PROG)

$(ROOT_PROG_LINK) := FILEMODE = 0555

LOCAL_OBJS = fcinfo.o fcinfo-list.o fcadm-list.o printAttrs.o fcoeadm.o
COMMON_OBJS = cmdparse.o
LOCAL_SRCS = $(LOCAL_OBJS:%.o=%.c)
COMMON_SRCS = $(COMMON_OBJS:%.o=$(COMMONBASE)/cmdparse/%.c)
OBJS = $(LOCAL_OBJS) $(COMMON_OBJS)
SRCS =  $(LOCAL_SRCS) $(COMMON_SRCS)

include ../Makefile.cmd

POFILE = fcinfo_cmd.po
POFILES = fcinfo.po fcinfo-list.po fcadm-list.po printAttrs.po fcoeadm.po

CERRWARN += -_gcc=-Wno-unused-variable

# not linted
SMATCH=off

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)

LDLIBS += -lHBAAPI
LDLIBS += -lfcoe
LDLIBS += -lscf

INCS += -I.
INCS += -I$(SRC)/lib/hbaapi/common
INCS += -I$(COMMONBASE)/cmdparse
INCS += -I$(SRC)/lib/libfcoe/common

CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_REENTRANT $(INCS)
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

LINTFLAGS	+= -erroff=E_SUSPICIOUS_COMPARISON
LINTFLAGS	+= -erroff=E_SEC_SPRINTF_UNBOUNDED_COPY
LINTFLAGS	+= -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTFLAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTFLAGS	+= -erroff=E_NAME_USED_NOT_DEF2
LINTFLAGS	+= -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTFLAGS	+= -erroff=E_STATIC_UNUSED

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(ROOT_PROG_LINK): $(ROOTUSRSBIN)/$(PROG)
	-$(RM) $@
	$(LN) $(ROOTUSRSBIN)/$(PROG) $@

install: all $(ROOTMANIFEST) $(ROOTSVCMETHOD) $(ROOTUSRSBINPROG) $(ROOT_PROG_LINK)

cmdparse.o: $(COMMONBASE)/cmdparse/cmdparse.c
	$(COMPILE.c) -o $@ $(COMMONBASE)/cmdparse/cmdparse.c
	$(POST_PROCESS_O)
$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@
clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

check:	$(CHKMANIFEST)

# Links from /usr/sbin to /sbin
$(ROOTUSRSBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(@F) $@

include ../Makefile.targ
