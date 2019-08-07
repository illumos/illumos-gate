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
# Copyright (c) 2018, Joyent, Inc.

PROG= filesync

OBJS= action.o anal.o base.o debug.o files.o ignore.o main.o recon.o rename.o rules.o acls.o eval.o
SRCS= $(OBJS:%.o=%.c)
HDRS= filesync.h messages.h database.h

include ../Makefile.cmd

LDLIBS += -lgen

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)

# not linted
SMATCH=off

FILEMODE= 0555

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG)

$(OBJS): $(HDRS)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

#
# we need our own rule for building a message catalog because our strings 
# are already extracted, and xgettext expects to find them in situ.
#
#	The sed command turns each string define in messages.h into
#	a call to gettext, so that xgettext can extract them.  Also
#	we capture all comments, since the only comments in messages.h
#	are for the benefit of the translators.
#
$(POFILE): messages.h
	$(SED) -e "s/#define/gettext(/" -e "/gettext/s/$$/)/" messages.h | \
	$(XGETTEXT) -c "" -d $(TEXT_DOMAIN) -
	$(MV) $(TEXT_DOMAIN).po $@

include ../Makefile.targ
