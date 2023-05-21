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

include ../Makefile.cmd

COMMONBASE = ../../common

PROG = sasinfo
PRODUCT = $(PROG)

$(ROOT_PROG_LINK) := FILEMODE = 0555

LOCAL_OBJS = sasinfo.o sasinfo-list.o printAttrs.o
COMMON_OBJS = cmdparse.o
OBJS = $(LOCAL_OBJS) $(COMMON_OBJS)
POFILE = sasinfo_all.po
POFILES = $(LOCAL_OBJS:%.o=%.po)


LDLIBS += -lSMHBAAPI

CERRWARN += -_gcc=-Wno-unused-value

SMOFF += indenting

INCS += -I.
INCS += -I$(SRC)/lib/smhba/common
INCS += -I$(SRC)/lib/hbaapi/common
INCS += -I$(COMMONBASE)/cmdparse

CPPFLAGS += -D_LARGEFILE64_SOURCE=1 -D_REENTRANT $(INCS)
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

cmdparse.o: $(COMMONBASE)/cmdparse/cmdparse.c
	$(COMPILE.c) -o $@ $(COMMONBASE)/cmdparse/cmdparse.c
	$(POST_PROCESS_O)

install: all $(ROOTUSRSBINPROG)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

clean:
	$(RM) $(OBJS)

check:	$(CHKMANIFEST)

include ../Makefile.targ
