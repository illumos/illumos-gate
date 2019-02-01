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
# Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

include		$(SRC)/cmd/sgs/librtld/Makefile.com

CPPFLAGS +=	-I../../../../uts/sparc/krtld

.KEEP_STATE:

ROOTFS_DYNLIB64 =	$(DYNLIB:%=$(ROOTFS_LIBDIR64)/%)
$(ROOTFS_DYNLIB64) :=	FILEMODE=755

all:		$(DYNLIB) $(LIBLINKS)

install:	all $(ROOTFS_DYNLIB64)

CPPFLAGS +=	-D_ELF64


include		$(SRC)/cmd/sgs/librtld/Makefile.targ
include		../../Makefile.sub.64

CONVLIBDIR =	$(CONVLIBDIR64)
ELFLIBDIR =	$(ELFLIBDIR64)
