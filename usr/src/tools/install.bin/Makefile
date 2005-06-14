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
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# tools/install.bin/Makefile
#

PROG=	install.bin
OBJS=	$(PROG).o
SRCS=	$(OBJS:%.o=%.c)

include ../Makefile.tools

OWNER=	root
GROUP=	bin
CFLAGS += $(CCVERBOSE)
LDLIBS += -lgen

.KEEP_STATE:

all:	$(PROG)

install: all .WAIT $(ROOTONBLDMACHPROG)
	$(RM) $(ROOTONBLDBINMACH)/install
	$(LN) $(ROOTONBLDMACHPROG) $(ROOTONBLDBINMACH)/install

lint:	lint_SRCS

clean:
	$(RM) $(CLEANFILES)

include ../Makefile.targ
