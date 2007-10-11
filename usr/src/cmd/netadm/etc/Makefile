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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Makefile for /etc/flash/
#
#
# cmd/netadm/etc/Makefile

include ../../Makefile.cmd

FLASHTTYDEFS= ttydefs.cleanup.sh
FLASHPOSTPROG= $(FLASHTTYDEFS:%.sh=%)

ETCFLASHD=	$(ROOTETC)/flash
ETCFLASHPOSTD=	$(ROOTETC)/flash/postdeployment

DIRS=	$(ETCFLASHD) $(ETCFLASHPOSTD)

ETCFLASHPOSTPROG= $(FLASHPOSTPROG:%=$(ETCFLASHPOSTD)/%)

$(ETCFLASHD) :=	DIRMODE=	755
$(ETCFLASHD) :=	OWNER=          root
$(ETCFLASHD) :=	GROUP=          sys
$(ETCFLASHPOSTD) :=	DIRMODE=	755
$(ETCFLASHPOSTD) :=	OWNER=          root
$(ETCFLASHPOSTD) :=	GROUP=          sys
$(ETCFLASHPOSTPROG) :=	FILEMODE=       0744
$(ETCFLASHPOSTPROG) :=	OWNER=          root
$(ETCFLASHPOSTPROG) :=	GROUP=          sys

.KEEP_STATE:

all:  $(FLASHPOSTPROG)

install: all .WAIT $(DIRS) .WAIT $(ETCFLASHPOSTPROG)

cstyle:

lint:

$(DIRS):
	$(INS.dir)

$(ETCFLASHPOSTD)/% : %
	$(INS.file)

clean:
	$(RM) $(FLASHPOSTPROG)
