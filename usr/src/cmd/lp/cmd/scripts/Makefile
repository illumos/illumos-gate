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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/lp/cmd/scripts/Makefile
#


include	$(SRC)/cmd/Makefile.cmd

USRSBINPROG = lpshut
ROOTUSRSBINPROG=	$(USRSBINPROG:%=$(ROOTUSRSBIN)/%)
$(ROOTUSRSBINPROG)	:= FILEMODE=555

LIBPROG =	lpsched
ROOTLIBPROG=	$(LIBPROG:%=$(ROOTLIB)/%)
$(ROOTLIBPROG)	:= FILEMODE=555

MSGFILES=	lpsched lpshut
POFILE=		lpschedlpshut.po

LIBLINKS = lpshut
ROOTSYMLINKS=   $(LIBLINKS:%=$(ROOTLIB)/%)

.KEEP_STATE:

all:	$(USRSBINPROG) $(LIBPROG)

install:	$(ROOTUSRSBINPROG) $(ROOTLIBPROG) $(ROOTSYMLINKS)

catalog:	$(POFILE)
	$(CP) $(POFILE) ..

_msg:   $(POFILE)

$(POFILE): $(MSGFILES)
	grep gettext $(MSGFILES) | tr '`' ' ' | sed -e "s/gettext \"/gettext \(\"/" | sed -e "s/$$/);/"  > $(POFILE).i
	$(XGETTEXT) -s $(POFILE).i
	$(RM) $@ $(POFILE).i
	mv messages.po $(POFILE)

#
# Create a message file to test with
#
_msg_test:
	grep gettext $(MSGFILES) | tr '`' ' ' | sed -e "s/gettext \"/gettext \(\"/" | sed -e "s/$$/);/"  > $(POFILE).i
	$(XGETTEXT) -s -m "xxx" $(POFILE).i
	$(RM) $@ $(POFILE).i
	mv messages.po $(POFILE)

clean:
	$(RM) $(POFILE)

clobber: clean

$(ROOTSYMLINKS):
		$(RM) $@; $(SYMLINK) ../sbin/$(@F) $@
