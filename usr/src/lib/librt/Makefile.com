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
#

LIBRARY =	librt.a
VERS =		.1

include		$(SRC)/lib/Makefile.rootfs

DYNFLAGS +=	-F libc.so.1

COMPATLINKS +=	lib/libposix4.so.1 \
		lib/libposix4.so \
		usr/lib/libposix4.so.1 \
		usr/lib/libposix4.so

COMPATLINKS64 +=	lib/$(MACH64)/libposix4.so.1 \
			lib/$(MACH64)/libposix4.so \
			usr/lib/$(MACH64)/libposix4.so.1 \
			usr/lib/$(MACH64)/libposix4.so

$(ROOT)/lib/libposix4.so.1 := COMPATLINKTARGET=librt.so.1
$(ROOT)/lib/libposix4.so := COMPATLINKTARGET=libposix4.so.1
$(ROOT)/usr/lib/libposix4.so.1 := COMPATLINKTARGET=../../lib/librt.so.1
$(ROOT)/usr/lib/libposix4.so := COMPATLINKTARGET=../../lib/librt.so.1
$(ROOT)/lib/$(MACH64)/libposix4.so.1 := COMPATLINKTARGET=librt.so.1
$(ROOT)/lib/$(MACH64)/libposix4.so := COMPATLINKTARGET=libposix4.so.1
$(ROOT)/usr/lib/$(MACH64)/libposix4.so.1:= \
	COMPATLINKTARGET=../../../lib/$(MACH64)/librt.so.1
$(ROOT)/usr/lib/$(MACH64)/libposix4.so:= \
	COMPATLINKTARGET=../../../lib/$(MACH64)/librt.so.1
$(ROOT)/usr/lib/$(MACH64)/librt.so.1:= \
	COMPATLINKTARGET=../../../lib/$(MACH64)/librt.so.1
$(ROOT)/usr/lib/$(MACH64)/librt.so:= \
	COMPATLINKTARGET=../../../lib/$(MACH64)/librt.so.1
