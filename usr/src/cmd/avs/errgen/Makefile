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
DYNPROG=	errgen

include ../../Makefile.cmd
include ../Makefile.com

PROG=	$(DYNPROG)

OBJS=	errgen.o

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-switch
LINTFLAGS += -erroff=E_SEC_SPRINTF_UNBOUNDED_COPY
CLOBBERFILES += $(DYNPROG)

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG)

install: all

lint:	lint_PROG

clean:
	$(RM) $(OBJS)

$(PROG):	$(OBJS)
	$(NATIVECC) $(CFLAGS) $(OBJS) -o $@
	$(POST_PROCESS)

include	../../Makefile.targ
