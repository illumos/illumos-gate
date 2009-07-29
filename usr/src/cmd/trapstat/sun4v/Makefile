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

PLATFORM = sun4v
PLATLINKS =
CLASS = 32
SRCDIR=../sun4

include ../../Makefile.cmd
include ../../../Makefile.psm

PROG= trapstat
OBJS= trapstat.o
SRCS= $(OBJS:%.o=$(SRCDIR)/%.c)

CFLAGS += -v -Dsun4v
IFLAGS = -I$(USR_PSM_INCL_DIR)
CPPFLAGS += $(IFLAGS) $(ARCHOPTS) -Dsun4v
LINTFLAGS += $(LDLIBS) -u

FILEMODE= 0555

CLEANFILES += $(OBJS)

%.o : $(SRCDIR)/%.c
	$(COMPILE.c) $<

.KEEP_STATE:

all: $(PROG)

install:	all $(USR_PSM_SBIN_PROG) $(USR_PSM_SBIN_PROG_LINKS)

$(PROG):	$(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	-$(RM) $(CLEANFILES)

lint:	lint_SRCS

include ../../Makefile.targ
include ../../../Makefile.psm.targ
