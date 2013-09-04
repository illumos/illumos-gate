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
#
# Makefile definitions for volume management
#
#
# cmd/lvm/Makefile
#

include ../Makefile.cmd

SUBDIRS   = md_monitord util rpc.metad rpc.metamhd rpc.metamedd etc
SUBDIRS  += rpc.mdcommd metassist
POSUBDIRS = md_monitord util rpc.metad rpc.mdcommd metassist

CAT=	cat

#
# for messaging catalog
#
POFILE= SUNW_MD.po
POFILES= $(POSUBDIRS:%=%/%p.po)

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
cstyle :=	TARGET= cstyle
_msg :=		TARGET= catalog

.KEEP_STATE:

all install clean cstyle lint: $(SUBDIRS)

clobber: $(SUBDIRS)
	$(RM) $(CLOBBERFILES)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(POFILE): $(POFILES)
	$(BUILDPO.pofiles)

_msg:   $(POSUBDIRS) .WAIT $(MSGDOMAINPOFILE)

FRC:

include $(SRC)/Makefile.msg.targ
