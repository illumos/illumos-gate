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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1991-2000 by Sun Microsystems, Inc.
# All rights reserved.
#

TXTS= nsswitch.conf netconfig hosts services

include ../Makefile.cmd

FILES= hosts services
ETCFILES= netconfig nsswitch.conf nsswitch.files nsswitch.nis nsswitch.nisplus \
		nsswitch.dns nsswitch.ldap 
ETCDEFAULTFILES= nss

ROOTNET=    $(ROOTETC)/net
TICLTS=     $(ROOTNET)/ticlts
TICOTS=     $(ROOTNET)/ticots
TICOTSORD=  $(ROOTNET)/ticotsord

ROOTDIRS= \
	$(ROOTNET) \
	$(TICLTS) \
	$(TICOTS) \
	$(TICOTSORD)

ITICLTSFILES=		$(FILES:%=$(TICLTS)/%)
ITICOTSFILES=		$(FILES:%=$(TICOTS)/%)
ITICOTSORDFILES=	$(FILES:%=$(TICOTSORD)/%)
IETCFILES=			$(ETCFILES:%=$(ROOTETC)/%)
IETCDEFAULTFILES=	$(ETCDEFAULTFILES:%=$(ROOTETC)/default/%)

FILEMODE= 0644
OWNER= root
GROUP= sys

$(TICLTS)/% $(TICOTS)/% $(TICOTSORD)/% $(ROOTETC)/% $(ROOTETC)/default/%: %
	$(INS.file)

.KEEP_STATE:

all: $(TXTS)

install: all $(ROOTDIRS) $(ITICLTSFILES) $(ITICOTSFILES) $(ITICOTSORDFILES) \
			$(IETCFILES) $(IETCDEFAULTFILES)

$(ROOTDIRS):
	$(INS.dir)

FRC:

clean clobber lint:

