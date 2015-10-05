#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG= codereview

OBJS= 	lwlp.o
SRCS=	$(OBJS:%.o=%.c)
CLEANFILES += $(OBJS)
TMPDIR= /tmp

include ../Makefile.tools

CERRWARN += -_gcc=-Wno-parentheses

MAN1ONBLDFILES= codereview.1onbld

$(ROOTONBLDMAN1ONBLDFILES) := FILEMODE=      644

COPTS=	-O

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:	$(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT  $(ROOTONBLDMACHPROG) $(ROOTONBLDMAN1ONBLDFILES)

clean:
	$(RM) $(CLEANFILES)

lint: lint_SRCS

include ../Makefile.targ
