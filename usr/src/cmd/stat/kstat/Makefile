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

PROG = kstat
OBJS = kstat.o
SRCS =$(OBJS:%.o=%.c) $(COMMON_SRCS)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/stat/Makefile.stat

LDLIBS += -lavl -lcmdutils -ldevinfo -lgen -lkstat
CFLAGS += $(CCVERBOSE) -I${STATCOMMONDIR}
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-parentheses

CPPFLAGS_sparc += -I$(SRC)/uts/sfmmu
CPPFLAGS_sparc += -I$(SRC)/uts/sun4u/sunfire
CPPFLAGS += $(CPPFLAGS_$(MACH))

FILEMODE= 0555

lint := LINTFLAGS = -muxs -I$(STATCOMMONDIR)

#
# Maddeningly, lint both chokes on "%hhx" in a format string and refuses to be
# suppressed about it (ironically further complaining that the suppression
# directive itself is unused -- without suppressing the error itself).  So we
# must unfortunately disable E_BAD_FORMAT_STR2 entirely...
#
lint := LINTFLAGS += -xerroff=E_BAD_FORMAT_STR2

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG)

$(PROG): $(OBJS) $(COMMON_OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o : $(STATCOMMONDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

clean:
	-$(RM) $(OBJS) $(COMMON_OBJS)

lint: lint_SRCS

include $(SRC)/cmd/Makefile.targ
