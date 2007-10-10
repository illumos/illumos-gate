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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# usr/src/cmd/cmd-inet/lib/nwamd/Makefile
#

# Needed for ROOTFS_LIBDIR definition
include		../../../../lib/Makefile.lib

PROG=		nwamd
OBJS=		events.o interface.o llp.o main.o \
		state_machine.o util.o wireless.o
SRCS=		$(OBJS:%.o=%.c)
HEADERS=	defines.h functions.h structures.h variables.h

include		../../../Makefile.cmd

POFILE=		$(PROG).po
POFILES=	interface.po wireless.po

ROOTCMDDIR=	$(ROOTFS_LIBDIR)/inet

LDLIBS +=	-lsocket -lnsl -linetcfg -linetutil -lumem -lscf -ldladm -lgen

.KEEP_STATE:

.PARALLEL:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: $(ROOTCMD)

check:  $(SRCS) $(HEADERS)
	$(CSTYLE) -cpP $(SRCS) $(HEADERS)

$(ROOTCMD): all

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include		../../../Makefile.targ
include		../../Makefile.msg
