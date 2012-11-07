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

include $(SRCDIR)/../Makefile.cmd
include $(SRCDIR)/../../Makefile.psm

PROG		= prtdiag
OBJS		= main.o
CLASS		= 32

CERRWARN	+= -_gcc=-Wno-parentheses

FILEMODE	= 2755
DIRMODE		= 755

LINT_OBJS	= $(OBJS:%.o=%.ln)
POFILE		= prtdiag.po
POFILES		= $(OBJS:%.o=%.po)

LIBPRTDIAG	= $(SRC)/lib/libprtdiag

.PARALLEL: $(OBJS) $(LINT_OBJS)

%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o: $(SRCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.po: %.c
	$(COMPILE.cpp) $<  > $<.i
	$(BUILD.po)

%.po: $(SRCDIR)/%.c
	$(COMPILE.cpp) $<  > $<.i
	$(BUILD.po)

%.ln: %.c
	$(LINT.c) -c $<

%.ln: $(SRCDIR)/%.c
	$(LINT.c) -c $<
