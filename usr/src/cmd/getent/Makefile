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
# Copyright (c) 2018 Peter Tribble.
# Copyright (c) 2014 Gary Mills
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=	getent

include ../Makefile.cmd

OBJECTS= \
	dogetauthattr.o	\
	dogetethers.o	\
	dogetexecattr.o	\
	dogetgr.o	\
	dogethost.o	\
	dogetipnodes.o	\
	dogetnet.o	\
	dogetnetmask.o	\
	dogetprofattr.o	\
	dogetproject.o	\
	dogetproto.o	\
	dogetpw.o	\
	dogetsp.o	\
	dogetserv.o	\
	dogetuserattr.o	\
	getent.o

SRCS=	$(OBJECTS:.o=.c)

LDLIBS	+= -lsecdb -lsocket -lnsl -lproject

#
# for message catalog
#
POFILE= gettent.po
POFILES= $(SRCS:%.c=%.po)

.KEEP_STATE:

all: $(PROG)

$(POFILE):      $(POFILES)
	$(RM)	$@
	cat     $(POFILES)      > $@


$(PROG): $(OBJECTS)
	$(LINK.c) -o $@ $(OBJECTS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJECTS)

lint:	lint_SRCS

include ../Makefile.targ
