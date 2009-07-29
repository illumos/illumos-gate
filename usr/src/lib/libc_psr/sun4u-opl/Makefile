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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm

PLATFORM=	sun4u-opl

SUBDIRS=	$(MACH)
SUBDIRS64=	$(MACH64)

all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber

MODULE		= libc_psr.so.1
LIBC_PSR_DIRS	= $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib)
LIBC_PSR_LINKS	= $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MODULE))
INS.slink6	= $(RM) -r $@; $(SYMLINK) ../../$(PLATFORM)/lib/$(MODULE) $@
LIBC_PSR64_DIRS	= $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MACH64))
LIBC_PSR64_LINKS = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MACH64)/$(MODULE))
INS.slink7	= $(RM) -r $@; $(SYMLINK) ../../../$(PLATFORM)/lib/$(MACH64)/$(MODULE) $@

#
# Used when building links in /platform/$(PLATFORM)/lib
#
LINKED_PLATFORMS	= SUNW,SPARC-Enterprise

all install: lib32 $(BUILD64) lib64 $(LIBC_PSR_LINKS) $(LIBC_PSR64_LINKS)

clean clobber: lib32 $(BUILD64) lib64

$(LIBC_PSR_DIRS):
	-$(INS.dir.root.bin)

$(LIBC_PSR_LINKS): $(LIBC_PSR_DIRS)
	-$(INS.slink6)

$(LIBC_PSR64_DIRS):
	-$(INS.dir.root.bin)

$(LIBC_PSR64_LINKS): $(LIBC_PSR64_DIRS)
	-$(INS.slink7)

lint:
	@ $(ECHO) "Nothing to lint here: skipping"

lib32: $(SUBDIRS)

lib64: $(SUBDIRS64)

$(SUBDIRS) $(SUBDIRS64): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
