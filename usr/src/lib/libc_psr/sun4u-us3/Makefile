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

PLATFORM	=	sun4u-us3

all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber

TOUCH		= /usr/bin/touch

MODULE		= libc_psr.so.1
LIBC_PSR_DIRS   = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib)
LIBC_PSR_LINKS  = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MODULE))
INS.slink6      = $(RM) -r $@; $(SYMLINK) ../../$(PLATFORM)/lib/$(MODULE) $@
LIBC_PSR64_DIRS	= $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MACH64))
LIBC_PSR64_LINKS = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MACH64)/$(MODULE))
INS.slink7	= $(RM) -r $@; $(SYMLINK) ../../../$(PLATFORM)/lib/$(MACH64)/$(MODULE) $@

#
# Used when building links in /platform/$(PLATFORM)/lib
#
LINKED_PLATFORMS	= SUNW,Sun-Blade-1000
LINKED_PLATFORMS	+= SUNW,Sun-Blade-1500
LINKED_PLATFORMS	+= SUNW,Sun-Blade-2500
LINKED_PLATFORMS	+= SUNW,A70
LINKED_PLATFORMS	+= SUNW,Sun-Fire
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V240
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V250
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V440
LINKED_PLATFORMS	+= SUNW,Sun-Fire-280R
LINKED_PLATFORMS	+= SUNW,Sun-Fire-15000
LINKED_PLATFORMS	+= SUNW,Sun-Fire-880
LINKED_PLATFORMS	+= SUNW,Sun-Fire-480R
LINKED_PLATFORMS	+= SUNW,Netra-T12
LINKED_PLATFORMS	+= SUNW,Netra-T4
LINKED_PLATFORMS	+= SUNW,Netra-CP3010
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V215
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V445

$(ROOT_PSM_LIB_DIR):
	-$(INS.dir)

$(ROOT_PSM_LIB_DIR)/$(MODULE):	$(ROOT_PSM_LIB_DIR) $(MODULE)
	$(RM) -r $@; $(INS) -s -f $(@D) $(MODULE)

$(ROOT_PSM_LIB64_DIR):
	-$(INS.dir)

$(ROOT_PSM_LIB64_DIR)/$(MODULE):	$(ROOT_PSM_LIB64_DIR) $(MODULE)
	$(RM) -r $@; $(INS) -s -f $(@D) $(MODULE)

$(LIBC_PSR_DIRS):
	-$(INS.dir)

$(LIBC_PSR_LINKS): $(LIBC_PSR_DIRS)
	-$(INS.slink6)

$(LIBC_PSR64_DIRS):
	-$(INS.dir)

$(LIBC_PSR64_LINKS): $(LIBC_PSR64_DIRS)
	-$(INS.slink7)

all:	FRC
	@$(TOUCH) $(MODULE)

install:	all $(ROOT_PSM_LIB_DIR)/$(MODULE) $(ROOT_PSM_LIB64_DIR)/$(MODULE) $(LIBC_PSR_LINKS) $(LIBC_PSR64_LINKS)

clean clobber : FRC
	$(RM) $(MODULE)

lint:
	@ $(ECHO) "Nothing to lint here: skipping"

FRC:
