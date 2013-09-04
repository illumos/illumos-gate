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

include	../Makefile.lib

SUBDIRS=	$(MACH)
XGETTEXT=	$(GNUXGETTEXT)
XGETFLAGS=	$(GNUXGETFLAGS)

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint

MSGFIND =	$(FIND) . -name '*.py' -o -name '*.c'
MSGFILES =	$(MSGFIND:sh)
PYCFIND =	$(FIND) . -name '*.pyc'
PYCFILES = 	$(PYCFIND:sh)
POFILE =	pyzfs.po

.KEEP_STATE:

all install clean lint: $(SUBDIRS)
clobber: $(SUBDIRS)
	$(RM) $(POFILE) $(PYCFILES)

$(POFILE):	pofile_MSGFILES

_msg: $(MSGDOMAINPOFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../../Makefile.msg.targ
