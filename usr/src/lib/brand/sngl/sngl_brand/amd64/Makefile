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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2012, Joyent, Inc. All rights reserved.
#

ISAOBJDIR =	$(BRAND_SHARED)/brand/amd64/pics/

include ../Makefile.com
include $(SRC)/lib/Makefile.lib.64

CPPFLAGS +=     -I$(BRAND_SHARED)/brand/amd64

#
# see ../Makefile.com for why we MUST explicity make ld.so.1 our interpreter
#
DYNFLAGS +=		-Wl,-I/lib/64/ld.so.1
CPPFLAGS += 		-D_SYSCALL32

# Note that we also set the runtime path for the emulation library to point
# into /system. This is an attempt to ensure that our brand library get's the
# native version of libmapmallc.
#
DYNFLAGS +=	-R/lib/64 -R/system/usr/lib/64

CLEANFILES +=		$(DYNLIB)
CLOBBERFILES +=		$(ROOTLIBS64)

install: all $(ROOTLIBS64)
