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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libc/i386_hwcap3/Makefile
#

LIBCBASE=	../i386

LIBRARY=	libc_hwcap3.a

EXTN_CPPFLAGS=	-D_CMOV_INSN -D_SSE_INSN -D_MMX_INSN
EXTN_CFLAGS=	-xtarget=pentium_pro
EXTN_DYNFLAGS=	-M mapfile

# Defining this means build targets will first try to use source from this
# directory before falling back to unoptimized i386 source.
#
# Currently, the only differences between hwcap3 and hwcap1 is the kernel entry
# method (hwcap1 uses "sysenter" and hwcap2 uses "syscall" while hwcap3 uses
# "int 0x91".  So for now, build libc_hwcap3 with the optimized sources for
# libc_hwcap1.
#
OPTIMIZED_LIBCBASE=../i386_hwcap1

include ../i386/Makefile.com
