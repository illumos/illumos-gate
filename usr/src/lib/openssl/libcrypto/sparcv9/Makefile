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

include ../Makefile.com
include ../../../Makefile.lib.64

# Override the default specified in ../Makefile.com
MD5_OBJ_ASM=	md5/asm/md5-sparcv9.o

# suppress this specific warning triggered by SS12 compiler. We do it here so
# that we don't have to change the source code using pragma directives. The
# issue is that acomp is not equipped to perform control flow checks on demand
# so warning can be issued on an invalid construct even when the construct is
# not reachable, like this:
#
#	char c, buf[10];
#	if (0 != 0)
#		c = buf[-1];
#
$(__SSNEXT)CFLAGS64 += -erroff=E_BAD_VAR_ADDRESS_ARITH

# lint doesn't like asm files
lint :=	MD5_OBJ_ASM =
lint :=	BN_ASM =

CFLAGS64 += -DMD5_ASM \
	-erroff=E_TYP_STORAGE_CLASS_OBSOLESCENT \
	-erroff=E_CONST_PROMOTED_UNSIGNED_LONG

pics/md5/asm/md5-sparcv9.o := CFLAGS64 += -DMD5_BLOCK_DATA_ORDER

install: all $(ROOTLIBS64) $(ROOTLINKS64) $(ROOTLINT64)
