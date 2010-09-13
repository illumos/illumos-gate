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
# uts/sun4u/snowbird/sys/Makefile
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
UTSBASE	= ../../..

#
# include global definitions
#
include ../Makefile.snowbird

#
# Override defaults.
#
FILEMODE	 = 644

HDRS=		todds1307.h

ROOTDIR=	$(ROOT)/usr/include/sys

ROOTHDRS=	$(HDRS:%=$(ROOTDIR)/%)

CHECKHDRS=	$(HDRS:%.h=%.check)

.KEEP_STATE:

.PARALLEL:	$(CHECKHDRS) $(ROOTHDRS)

install_h:

check:		$(CHECKHDRS)

#
# install rules
#
$(ROOTDIR)/%: %	$(ROOTDIR)
	$(INS.file)

$(ROOTDIR):
	$(INS.dir)

FRC:

include ../Makefile.targ
