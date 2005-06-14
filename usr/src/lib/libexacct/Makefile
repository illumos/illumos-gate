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
# Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libexacct/Makefile
#

include ../Makefile.lib

SUBDIRS=	$(MACH) demo
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET = all
debug :=	TARGET = debug
clean :=	TARGET = clean
clobber :=	TARGET = clobber
delete :=	TARGET = delete
install :=	TARGET = install
lint :=		TARGET = lint
_msg :=		TARGET = _msg
package :=	TARGET = package

LIBRARY=	libexacct.a
TEXT_DOMAIN=	SUNW_OS_OSLIB
XGETFLAGS=	-a
POFILE=		$(LIBRARY:.a=.po)
POFILES=	generic.po

SED=	sed
GREP=	grep
CP=	cp

.KEEP_STATE:

all debug clean clobber delete install package: spec .WAIT $(SUBDIRS)

lint: $(SUBDIRS)

install_h: $(ROOTHDRS)

check: $(CHECKHDRS)

spec $(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

_msg:   $(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):      .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) *.[ch]*
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

FRC:

