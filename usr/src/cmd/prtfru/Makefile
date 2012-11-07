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
# cmd/prtfru/Makefile
#

PROG = prtfru
OBJS = $(PROG).o main.o
SRCS = $(OBJS:%.o=%.c)

include $(SRC)/cmd/Makefile.cmd

CFLAGS    += $(CCVERBOSE)
CERRWARN  += -_gcc=-Wno-switch
CERRWARN  += -_gcc=-Wno-parentheses
CPPFLAGS  += -I$(SRC)/lib/libfru/include \
             -I$(SRC)/lib/libfruutils
LINTFLAGS += -u
EXTRA_LDLIBS    = -lfru -lfrureg -lfruutils

FILEMODE = 755

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS) $(EXTRA_LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBIN) $(ROOTUSRSBINPROG)

$(ROOTUSRSBIN):
	$(INS.dir)

lint: lint_SRCS

POFILE  = $(PROG)_msg.po
POFILES = $(OBJS:%.o=%.po)

$(POFILE):      $(POFILES)
	$(RM) $@; cat $(POFILES) > $@

clean:
	$(RM) $(OBJS)

include $(SRC)/cmd/Makefile.targ
