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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2013 Saso Kiselkov. All rights reserved.
#

include		$(SRC)/lib/Makefile.lib

$(SPARC_BLD)CAPDIR = capabilities

SUBDIRS=	$(MACH) $(BUILD64) $(MACH64)

HDRS =		md4.h md5.h sha1.h sha2.h skein.h
HDRDIR =	common

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

all clean clobber install lint: \
		$(CAPDIR) .WAIT $(SUBDIRS)

install_h:	$(ROOTHDRS)

check:		$(CHECKHDRS)

$(CAPDIR) \
$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include		$(SRC)/lib/Makefile.targ
