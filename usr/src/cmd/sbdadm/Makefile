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

PROG =	sbdadm

include ../Makefile.cmd

COMMONBASE = ../../common
UTSBASE = ../../uts

LOCAL_OBJS = sbdadm.o
COMMON_OBJS = cmdparse.o
LOCAL_SRCS =	$(LOCAL_OBJS:%.o=%.c)
COMMON_SRCS =	$(COMMON_OBJS:%.o=$(COMMONBASE)/cmdparse/%.c)
OBJS =	$(LOCAL_OBJS) $(COMMON_OBJS)
SRCS = $(LOCAL_SRCS) $(COMMON_SRCS)
POFILE = sbdadm_all.po
POFILES = $(LOCAL_OBJS:%.o=%.po)

CPPFLAGS += -I. -I$(COMMONBASE)/cmdparse
LDLIBS += -lstmf
LINTFLAGS += -xerroff=E_BAD_PTR_CAST_ALIGN

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

check:	$(SRCS) $(CHKMANIFEST)
	$(CSTYLE) -pPc $(SRCS:%=%)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

cmdparse.o: $(COMMONBASE)/cmdparse/cmdparse.c
	    $(COMPILE.c) -o $@ $(COMMONBASE)/cmdparse/cmdparse.c
	    $(POST_PROCESS_O)

clean:
	$(RM) $(OBJS) $(POFILES) $(POFILE)

lint:	lint_SRCS

include ../Makefile.targ
