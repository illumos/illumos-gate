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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

TOPDIR =	../../../../..
PLATFORM =	i86pc
KARCH =		$(PLATFORM)
ARCHVERS =
ARCHOPTS =	-Di386 -D__i386 -DI386BOOT -DBOOTAMD64 -D_ELF64_SUPPORT
ARCHOPTS +=	-DMULTIBOOT

PLAT_C_SRC =
ARCH_C_SRC =
ARCH_S_SRC =	cpu_id.s idttab.s samuldiv64.s
START_S_SRC =	asm.s
BIOS_S_SRC =	biosint.s

TOOLSRC =	$(TOPDIR)/tools

include ../Makefile.com

$(ROOT_PSM_UNIBOOT):= OWNER= root
$(ROOT_PSM_UNIBOOT):= GROUP= sys
$(ROOT_PSM_UNIBOOT):= FILEMODE= 755

$(ROOT_PSM_BIOSINT):= OWNER= root
$(ROOT_PSM_BIOSINT):= GROUP= sys
$(ROOT_PSM_BIOSINT):= FILEMODE= 755
