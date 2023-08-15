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
# cmd/abi/appcert/etc/Makefile
#

include $(SRC)/cmd/Makefile.cmd

SUFFIXES += .in

.KEEP_STATE:

ROOTLIBAPPCERT= $(ROOT)/usr/lib/abi/appcert

ETC_FILES = etc.alt etc.scoped etc.tweaks etc.warn
MESSAGES = etc.warn.po
ETC_FILES_SRC = $(ETC_FILES:%=%.in)

DEST_FILES = $(ETC_FILES:%=$(ROOTLIBAPPCERT)/%)

CLEANFILES=	$(MESSAGES) $(ETC_FILES)

install :=	FILEMODE=	0444
install :=	DIRMODE=	0755

all: $(ETC_FILES)

install: all .WAIT $(DEST_FILES)

$(ROOTLIBAPPCERT)/%:   %
	$(INS.file)

%: %.in
	$(SED) -e 's,gettext("\([^"]*\)"),\1,' $< > $@

_msg: $(MSGDOMAIN) $(MESSAGES)
	$(CP) $(MESSAGES) $(MSGDOMAIN)

$(MSGDOMAIN):
	$(INS.dir)

%.po: %.in
	$(XGETTEXT) $(XGETFLAGS) $<
	$(RM) $@
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

lint:

clean:
	-$(RM) $(CLEANFILES)

clobber:	clean

