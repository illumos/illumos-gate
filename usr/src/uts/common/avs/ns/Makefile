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
# include global definitions
include ../../../../Makefile.master

HDRS= \
	model.h \
	contract.h \
	nsctl_inter.h \
	ncall_inter.h \
	nsctl.h

ROOTDIR=	$(ROOT)/usr/include/sys/nsctl

ROOTHDRS=	$(HDRS:%=$(ROOTDIR)/%)

# install rules
$(ROOTDIR)/%: %
	$(INS.file)

# standards checking rules
%.check:      %.h
	$(DOT_H_CHECK)

CHECKHDRS= $(HDRS:%.h=%.check)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS)

install_h: $(ROOTDIR) $(ROOTHDRS)

$(ROOTDIR):
	$(INS.dir)

check:	$(CHECKHDRS)
