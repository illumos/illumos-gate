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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG =	tpmadm

OBJS =	main.o \
	admin_cmds.o

include ../../Makefile.cmd

SRCS =	$(OBJS:%.o=%.c)
POFILES = $(OBJS:%.o=%.po)
POFILE = $(PROG)_msg.po
MSGFILES=$(SRCS:%.c=%.i)

CPPFLAGS += -xCC
LINTFLAGS += -XCC  -L$(ADJUNCT_PROTO)/usr/lib
LDLIBS += -ltspi -luuid

CLOBBERFILES = C.ln $(POFILE) $(POFILES)

.KEEP_STATE:

all : $(PROG)

$(PROG) : $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(DYNFLAGS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILE) : $(POFILES)
	$(RM) $@; $(CAT) $(POFILES) > $@

install : all $(ROOTPROG)

clean :
	$(RM) $(OBJS)

lint : lint_SRCS

include ../../Makefile.targ
