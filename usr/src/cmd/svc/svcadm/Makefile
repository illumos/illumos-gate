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
# Copyright 2012, Joyent, Inc.  All rights reserved.
#

PROG =		svcadm
OBJS =		svcadm.o synch.o
SRCS =		$(OBJS:%.o=%.c)
POFILES = 	$(OBJS:.o=.po)

include ../../Makefile.cmd

POFILE = 	$(PROG)_all.po
LDLIBS +=	-lscf -luutil -lcontract

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	$(CNOWARN_UNINIT)

lint := LINTFLAGS = -ux

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTSBINPROG) $(ROOTUSRSBINPROG)

$(ROOTUSRSBINPROG):
	-$(RM) $@
	-$(SYMLINK) ../../sbin/$(PROG) $@

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

include ../../Makefile.targ
