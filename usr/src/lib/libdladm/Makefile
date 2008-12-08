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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

include $(SRC)/lib/Makefile.lib

HDRS =		libdladm.h libdladm_impl.h libdllink.h libdlaggr.h	\
		libdlwlan.h libdlwlan_impl.h libdlvnic.h libdlvlan.h	\
		libdlmgmt.h libdlflow.h libdlflow_impl.h libdlstat.h	\
		libdlether.h

HDRDIR =	common

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

POFILE =	libdladm.po
MSGFILES =	common/libdladm.c common/linkprop.c common/secobj.c	\
		common/libdllink.c common/libdlaggr.c	\
		common/libdlwlan.c common/libdlvnic.c	\
		common/libdlvlan.c common/libdlmgmt.c	\
		common/flowattr.c common/flowprop.c	\
		common/propfuncs.c common/libdlflow.c \
		common/libdlstat.c common/flowattr.c	\
		common/libdlether.c

XGETFLAGS =     -a -x libdladm.xcl

all :=		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
install :=	TARGET = install
lint :=		TARGET = lint

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

install_h:	$(ROOTHDRS)

check:		$(CHECKHDRS)

$(POFILE):	pofile_MSGFILES

_msg:		$(MSGDOMAINPOFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/Makefile.msg.targ
include $(SRC)/lib/Makefile.targ
