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
# Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
#

include		$(SRC)/cmd/Makefile.cmd

sparc_CAPDIR =	capabilities
i386_CAPDIR =	i386
CAPDIR =	$($(MACH)_CAPDIR)

sparc_SUBDIRS =	sun4
i386_SUBDIRS =
SUBDIRS =	$($(MACH)_SUBDIRS)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

all clean clobber install lint: \
		$(CAPDIR) .WAIT $(SUBDIRS)

install_h check:

$(CAPDIR) \
$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include		$(SRC)/cmd/Makefile.targ
