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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

SRCS = mmsmnt.c

.KEEP_STATE:
.SUFFIXES:

PROG = mmsmnt

OBJS = $(SRCS:%.c=%.o)
lint_SRCS = $(SRCS:%.c=%.ln)

include $(SRC)/cmd/Makefile.cmd

ACSLSH = $(CLOSED)/lib/mms/h

FILEMODE = 4755

CFLAGS += $(CTF_FLAGS) $(CC_VERBOSE)
CFLAGS += -D_POSIX_PTHREAD_SEMANTICS

CPPFLAGS += -DMMS_OPENSSL -D_REENTRANT
CPPFLAGS += -I. -I../common -I$(SRC)/common/mms/mms
CPPFLAGS += -I$(SRC)/lib/mms/mms/common -I$(SRC)/lib/mms/mgmt/common
CPPFLAGS += -I$(ACSLSH)

LDLIBS += -lc -lnvpair
LDLIBS += -L$(SRC)/lib/mms/mms/$(MACH) -lmms
LDLIBS += -L$(SRC)/lib/mms/mgmt/$(MACH) -lmmsadm -R/usr/lib/mms

.NO_PARALLEL:
.PARALLEL: $(OBJS) $(lint_SRCS)

C99MODE=	$(C99_ENABLE)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(CTFMERGE) -L VERSION -o $@ $(OBJS)
	$(POST_PROCESS)

%.o: ../common/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

clean:
	$(RM) $(OBJS) $(lint_SRCS)

lint: $(lint_SRCS)

%.ln: ../common/%.c
	$(LINT.c) -c $<

install_h:

install: all $(ROOTBIN)/$(PROG)

include $(SRC)/cmd/Makefile.targ
