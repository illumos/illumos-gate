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
# Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
#


include		../../Makefile.master
include		../Makefile.lib

MANIFEST=	client.xml install.xml
MANIFESTDIR=	$(ROOT)/lib/svc/manifest/network/dns
ROOTMANIFEST=	$(MANIFEST:%=$(MANIFESTDIR)/%)

$(ROOTMANIFEST) :=	FILEMODE = 444

SVCMETHOD=	dns-install
SVCMETHODDIR=	$(ROOT)/lib/svc/method
ROOTSVCMETHOD=	$(SVCMETHOD:%=$(SVCMETHODDIR)/%)

$(ROOTSVCMETHOD) :=	FILEMODE = 0555

CHKMANIFEST=	$(MANIFEST:%.xml=%.xmlchk)

SUBDIRS=	include $(MACH)
$(BUILD64)SUBDIRS +=	$(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
_msg :=		TARGET= _msg

LIBRARY=	libresolv.a
TEXT_DOMAIN=	SUNW_OST_OSLIB
XGETFLAGS=	-a
POFILE=		$(LIBRARY:.a=.po)
POFILES=	generic.po

SED=	sed
GREP=	grep

.KEEP_STATE:

all clean clobber: $(SUBDIRS)

install: $(SUBDIRS) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

$(ROOTMANIFEST): $(MANIFESTDIR)

$(MANIFESTDIR):
	$(INS.dir)

$(MANIFESTDIR)/%: %
	$(INS.file)
$(ROOTSVCMETHOD): $(SVCMETHODDIR)

$(SVCMETHODDIR):
	$(INS.dir)

$(SVCMETHODDIR)/%: %
	$(INS.file)

# install rule for install_h target
$(ROOTHDRDIR)/%: %
	$(INS.file)

install_h: $(ROOTHDRS)

check: $(CHECKHDRS) $(CHKMANIFEST)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):	$(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) *.[ch]* */*.[ch]*
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET); echo

FRC:

