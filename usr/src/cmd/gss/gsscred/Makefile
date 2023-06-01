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
# Copyright (c) 2018, Joyent, Inc.

SBINPROG = gsscred

INCDIRS = -I. -I$(ROOT)/usr/include

LIBPATH = -L$(ROOT)/usr/lib

PROG= $(SBINPROG)

GSSCREDOBJS = gsscred.o gsscred_utils.o gsscred_file.o

OBJS	= $(GSSCREDOBJS)
SRCS	= $(OBJS:.o=.c)

include ../../Makefile.cmd

TEXT_DOMAIN = SUNW_OST_NETRPC
POFILE = $(PROG).po
POFILES = generic.po

ROOTBINPROG=		$(BINPROG:%=$(ROOTBIN)/%)

COPTFLAG += $(INCDIRS) $(LIBPATH)

# not linted
SMATCH=off

LDLIBS += -lgss

$(GPROGS) := CPPFLAGS += -DSYSV -DSunOS=50

.KEEP_STATE:

all: $(PROG)

gsscred:	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ROOTBINPROG):
	$(INS.dir)

$(ROOTUSRSBIN)/%:	%
	$(INS.file)

install: all $(DIRS) $(ROOTBINPROG) $(ROOTUSRSBIN)/gsscred

install_h:

clean:
	$(RM) $(OBJS)
	$(RM) $(PROG)

lint: lint_SRCS

include ../../Makefile.targ

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext *.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

FRC:
