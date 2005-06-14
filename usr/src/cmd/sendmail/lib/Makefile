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
# ident	"%Z%%M%	%I%	%E% SMI"
#

include			../../Makefile.cmd

SRCS=			aliases helpfile local-host-names trusted-users

MANIFEST=		smtp-sendmail.xml
ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)
ROOTMETHOD=		$(ROOTLIBSVCMETHOD)/smtp-sendmail

ROOTETCMAIL =		$(ROOTETC)/mail
ROOTETCMAILF =		$(ROOTETCMAIL)/aliases $(ROOTETCMAIL)/helpfile \
			$(ROOTETCMAIL)/local-host-names \
			$(ROOTETCMAIL)/trusted-users
ROOTETCSYMLINKS =	$(ROOTETC)/aliases
ROOTETCMAILSYMLINKS =	$(ROOTETCMAIL)/sendmail.hf

# conditional assignments
$(ROOTETCMAILF) :=	FILEMODE =	644
$(ROOTETCMAILF) :=	OWNER =		root

$(ROOTSVCNETWORK)/smtp-sendmail.xml := OWNER = root
$(ROOTSVCNETWORK)/smtp-sendmail.xml := GROUP = sys
$(ROOTSVCNETWORK)/smtp-sendmail.xml := FILEMODE = 0444

$(ROOT)/lib/svc/method/smtp-sendmail := OWNER = root
$(ROOT)/lib/svc/method/smtp-sendmail := GROUP = bin
$(ROOT)/lib/svc/method/smtp-sendmail := FILEMODE = 0555

.KEEP_STATE:

all:		$(SRCS)

install:	all $(ROOTETCMAILF) $(ROOTETCSYMLINKS) \
		$(ROOTETCMAILSYMLINKS) $(ROOTMANIFEST) $(ROOTMETHOD)

check:		$(CHKMANIFEST)

clean:

clobber:

lint:

$(ROOTETCMAIL)/%: %
	$(INS.file)

$(ROOTETCSYMLINKS):
	$(RM) $@; $(SYMLINK) mail/aliases $@

$(ROOTETCMAILSYMLINKS):
	$(RM) $@; $(SYMLINK) helpfile $@
