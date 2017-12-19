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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG= grep
FFILE= fgrep
EFILE= egrep

include ../Makefile.cmd

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized

ROOTXPG4LINKS = $(ROOTXPG4BIN)/$(FFILE)	$(ROOTXPG4BIN)/$(EFILE) $(ROOTXPG4BIN)/$(PROG)
ROOTLINKS = $(ROOTBIN)/$(FFILE) $(ROOTBIN)/$(EFILE)

CFLAGS += $(CCVERBOSE)
CPPFLAGS += -D_FILE_OFFSET_BITS=64

POFILE= grep_xpg4.po
POFILES= grep.po

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG) $(ROOTLINKS) $(ROOTXPG4LINKS)

$(ROOTLINKS):	$(ROOTPROG)
	-$(RM) $@
	-$(LN) $(ROOTPROG) $@

$(ROOTXPG4LINKS):	$(ROOTPROG)
	-$(RM) $@
	-$(SYMLINK) ../../bin/grep $@

$(POFILE): $(POFILES)
	$(RM) $@
	$(CP) $(POFILES) $@

# Make the links locally for test purposes
test:	$(FFILE) $(EFILE)

$(FFILE):      $(PROG)
		@$(RM) $(FFILE); $(LN) $(PROG) $(FFILE)

$(EFILE):      $(PROG)
		@$(RM) $(EFILE); $(LN) $(PROG) $(EFILE)

clean:

lint:	lint_PROG

include ../Makefile.targ
