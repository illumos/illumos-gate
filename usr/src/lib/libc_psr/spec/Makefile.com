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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1999-2000 by Sun Microsystems, Inc.
# All rights reserved.
#
# lib/libc_psr/spec/Makefile.com

include $(SRC)/Makefile.psm

MODULE=		abi


LINKED_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%)
LINKED_LIB_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib)
LINKED_ABI_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/abi)
LINKED_ABI_DIRS64 = $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/abi/$(MACH64))
ABI_LINKS32	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/abi/abi_$(DYNLIB))
ABI_LINKS64	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/abi/$(MACH64)/abi_$(DYNLIB))
ABI_LINKS	= $(ABI_LINKS$(CLASS))

INS.slink6	= $(RM) -r $@; $(SYMLINK) ../../../$(PLATFORM)/lib/abi/abi_$(DYNLIB) $@ $(CHOWNLINK) $(CHGRPLINK)
INS.slink7	= $(RM) -r $@; $(SYMLINK) ../../../../$(PLATFORM)/lib/abi/$(MACH64)/abi_$(DYNLIB) $@ $(CHOWNLINK) $(CHGRPLINK)

links:	$(ABI_LINKS$(CLASS))

$(LINKED_ABI_DIRS): $(LINKED_LIB_DIRS)
	-$(INS.dir.root.bin)

$(LINKED_ABI_DIRS64): $(LINKED_ABI_DIRS)
	-$(INS.dir.root.bin)

$(ABI_LINKS32): $(LINKED_ABI_DIRS)
	-$(INS.slink6)

$(ABI_LINKS64): $(LINKED_ABI_DIRS64)
	-$(INS.slink7)

FRC:
