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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include $(SRC)/cmd/wbem/Makefile.wbem

COMMON_SUBDIRS =	common \
			nfs_filesystem \
			nfs_share \
			assoc \
			nfs_mount

COMMON_SUBDIR_2 =	lib

SUBDIRS =		$(COMMON_SUBDIRS) $(COMMON_SUBDIR_2)

POFILE =	wbem_nfs.po
POFILES =	$(SUBDIRS:%=%/_%.po)

all:=		TARGET = all
clean:=		TARGET = clean
clobber:=	TARGET = clobber
install:=	TARGET = install
lint:=		TARGET = lint
check:=		TARGET = check
_msg:=		TARGET = catalog

.KEEP_STATE:

all clean install lint check: $(COMMON_SUBDIRS) .WAIT $(COMMON_SUBDIR_2)

clobber: $(SUBDIRS)
	$(RM) $(POFILE)

FRC:

${SUBDIRS}: FRC
	cd $@; pwd; $(MAKE) $(TARGET)

$(POFILE): $(POFILES)
	$(BUILDPO.pofiles)

_msg: $(SUBDIRS) .WAIT $(MSGDOMAINPOFILE)


include $(SRC)/Makefile.msg.targ
