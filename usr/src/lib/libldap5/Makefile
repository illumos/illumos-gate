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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include			../Makefile.lib

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint
_msg :=		TARGET= _msg

LIBRARY=        libldap.a
TEXT_DOMAIN =   SUNW_OST_OSLIB
XGETFLAGS=
POFILE=         $(LIBRARY:.a=.po)
POFILES=        generic.po

.KEEP_STATE:

all clean install: $(SUBDIRS)
clobber: $(SUBDIRS)
	$(RM) $(CLOBBERFILES)

lint:
	@ $(ECHO) "usr/src/lib/libldap5 is third-party code that"
	@ $(ECHO) "will never be made lint-clean: skipping"

# install rule for install_h target
$(ROOTHDRDIR)/%: %
	$(INS.file)

install_h: $(ROOTHDRS)

check: $(CHECKHDRS)

_msg:   $(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(RM) generic.po
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(MSGDOMAIN):
	$(INS.dir)

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS)  sources/ldap/*/*.[ch]*
	sed "/^domain/d" < messages.po  > $@
	$(RM) messages.po

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
