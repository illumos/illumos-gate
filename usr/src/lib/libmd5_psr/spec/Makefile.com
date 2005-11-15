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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# lib/libmd5_psr/spec/Makefile.com

include $(SRC)/Makefile.psm

MODULE=		abi

#
# links in /usr/platform
#
LINKED_PLATFORMS	= SUNW,Ultra-2
LINKED_PLATFORMS	+= SUNW,Ultra-4
LINKED_PLATFORMS	+= SUNW,Ultra-250
LINKED_PLATFORMS	+= SUNW,Ultra-Enterprise
LINKED_PLATFORMS	+= SUNW,Ultra-Enterprise-10000
LINKED_PLATFORMS	+= SUNW,UltraSPARC-IIi-Netract
LINKED_PLATFORMS	+= SUNW,UltraSPARC-IIe-NetraCT-40
LINKED_PLATFORMS	+= SUNW,UltraSPARC-IIe-NetraCT-60
LINKED_PLATFORMS	+= SUNW,Sun-Blade-100
LINKED_PLATFORMS	+= SUNW,Sun-Blade-1000
LINKED_PLATFORMS	+= SUNW,Sun-Blade-1500
LINKED_PLATFORMS	+= SUNW,Sun-Blade-2500
LINKED_PLATFORMS	+= SUNW,A70
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V445
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V215
LINKED_PLATFORMS	+= SUNW,Sun-Fire
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V240
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V250
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V440
LINKED_PLATFORMS	+= SUNW,Sun-Fire-280R
LINKED_PLATFORMS	+= SUNW,Sun-Fire-15000
LINKED_PLATFORMS	+= SUNW,Sun-Fire-880
LINKED_PLATFORMS	+= SUNW,Sun-Fire-480R
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V890
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V490
LINKED_PLATFORMS	+= SUNW,Serverblade1
LINKED_PLATFORMS	+= SUNW,Netra-T12
LINKED_PLATFORMS	+= SUNW,Netra-T4
LINKED_PLATFORMS	+= SUNW,Netra-CP2300
LINKED_PLATFORMS	+= SUNW,Netra-CP3010

LINKED_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%)
LINKED_LIB_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib)
LINKED_ABI_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/abi)
LINKED_ABI_DIRS64 = $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/abi/$(MACH64))
ABI_LINKS32	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/abi/abi_$(DYNLIB))
ABI_LINKS64	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/abi/$(MACH64)/abi_$(DYNLIB))
ABI_LINKS	= $(ABI_LINKS$(CLASS))

links:

FRC:
