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
#ident	"%W%	%E% SMI"
#
# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/cmd-inet/usr.sadm/dhcpmgr/help/art/Makefile

include $(SRC)/cmd/Makefile.cmd

HELPFILES= 	bannersmc.gif \
		dot1.gif \
		dot2.gif \
		folder.gif \
		macro2.gif \
		macroflow.gif \
		tip2.gif

ROOTHELPDIR=    $(ROOT)/usr/sadm/admin/dhcpmgr/help/art

ROOTDIRS= 	$(ROOTHELPDIR)

IHELPFILES=	$(HELPFILES:%=$(ROOTHELPDIR)/%)

MSGDIR=		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr/client/help/art
MSGDIRS =       $(ROOT)/usr/share/lib/locale \
                $(ROOT)/usr/share/lib/locale/com \
                $(ROOT)/usr/share/lib/locale/com/sun \
		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr \
		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr/client \
		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr/client/help \
		$(MSGDIR)

MSGFILES=	$(HELPFILES)
MSGS=		$(MSGFILES:%=$(MSGDIR)/%)

FILEMODE= 0444

$(ROOTHELPDIR)/%: %
	$(INS.file)

.KEEP_STATE:

all: $(HELPFILES)

install: all $(ROOTDIRS) $(IHELPFILES)

$(ROOTDIRS):
	$(INS.dir)

clean clobber lint:

_msg: $(MSGDIRS) $(MSGS)

$(MSGDIR)/%: %
	$(INS.file)

$(MSGDIRS):
	$(INS.dir)

