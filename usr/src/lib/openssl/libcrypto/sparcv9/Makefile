#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../Makefile.com

# Override the default specified in ../Makefile.com
MD5_OBJ_ASM=	md5/asm/md5-sparcv9.o

include ../../../Makefile.lib.64

CFLAGS64 += -DMD5_ASM \
	-erroff=E_TYP_STORAGE_CLASS_OBSOLESCENT \
	-erroff=E_CONST_PROMOTED_UNSIGNED_LONG

pics/$(MD5_OBJ_ASM) := CFLAGS64 += -DMD5_BLOCK_DATA_ORDER

install: all $(ROOTLIBS64) $(ROOTLINKS64) $(ROOTLINT64)
