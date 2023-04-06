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
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

include $(SRC)/lib/Makefile.lib
include ../Makefile.shared.com
include $(SRC)/lib/Makefile.rootfs

LDLIBS_i386 += -lsmbios
LDLIBS +=	-luutil -lc -lgen -lnvpair
LDLIBS +=	$(LDLIBS_$(MACH))

SRCDIR =	../common
COMDIR =	../../../common/svc

CPPFLAGS +=	-I$(SRC)/lib/libscf/inc -I$(SRC)/lib/libscf/common/inc \
	-I$(COMDIR) -I$(ROOTHDRDIR)
$(NOT_RELEASE_BUILD)CPPFLAGS += -DFASTREBOOT_DEBUG

.KEEP_STATE:

all:

include $(SRC)/lib/Makefile.targ
