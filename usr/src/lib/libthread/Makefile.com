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
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
#

LIBRARY =	libthread.a
VERS =		.1

include		$(SRC)/lib/Makefile.rootfs

DYNFLAGS +=	-F libc.so.1

COMPATLINKS +=	usr/lib/lwp/libthread.so.1 \
		usr/lib/lwp/libthread_db.so.1 \
		lib/libthread_db.so.1 \
		lib/libthread_db.so \
		usr/lib/libthread_db.so.1 \
		usr/lib/libthread_db.so

COMPATLINKS64 +=	usr/lib/lwp/$(MACH64)/libthread.so.1 \
			usr/lib/lwp/$(MACH64)/libthread_db.so.1 \
			lib/$(MACH64)/libthread_db.so.1 \
			lib/$(MACH64)/libthread_db.so \
			usr/lib/$(MACH64)/libthread_db.so.1 \
			usr/lib/$(MACH64)/libthread_db.so

$(ROOT)/usr/lib/lwp/libthread.so.1 := COMPATLINKTARGET=../libthread.so.1
$(ROOT)/usr/lib/lwp/libthread_db.so.1 := COMPATLINKTARGET=../libthread_db.so.1
$(ROOT)/usr/lib/lwp/$(MACH64)/libthread.so.1:= \
	COMPATLINKTARGET=../../$(MACH64)/libthread.so.1
$(ROOT)/usr/lib/lwp/$(MACH64)/libthread_db.so.1:= \
	COMPATLINKTARGET=../../$(MACH64)/libthread_db.so.1
$(ROOT)/lib/libthread_db.so.1 := COMPATLINKTARGET=libc_db.so.1
$(ROOT)/lib/libthread_db.so := COMPATLINKTARGET=libc_db.so.1
$(ROOT)/usr/lib/libthread_db.so.1 := COMPATLINKTARGET=../../lib/libc_db.so.1
$(ROOT)/usr/lib/libthread_db.so := COMPATLINKTARGET=../../lib/libc_db.so.1
$(ROOT)/lib/$(MACH64)/libthread_db.so.1 := COMPATLINKTARGET=libc_db.so.1
$(ROOT)/lib/$(MACH64)/libthread_db.so := COMPATLINKTARGET=libc_db.so.1
$(ROOT)/usr/lib/$(MACH64)/libthread_db.so.1:= \
	COMPATLINKTARGET=../../../lib/$(MACH64)/libc_db.so.1
$(ROOT)/usr/lib/$(MACH64)/libthread_db.so:= \
	COMPATLINKTARGET=../../../lib/$(MACH64)/libc_db.so.1
