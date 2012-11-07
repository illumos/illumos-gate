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

#
#	Path to the base of the uts directory tree.
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= scsa1394
OBJECTS		= $(SCSA1394_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(SCSA1394_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
WARLOCK_OUT     = $(SCSA1394_OBJS:%.o=%.ll)
WARLOCK_OK      = $(MODULE).ok
WLCMD_DIR       = $(UTSBASE)/common/io/warlock

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#       Overrides
#
ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)
CLEANLINTFILES	+= $(LINT32_FILES)

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE)

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV

#
# depends on
#
LDFLAGS		+= -dy -Nmisc/scsi -Nmisc/s1394 -Nmisc/sbp2

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized

#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK)

clobber:	$(CLOBBER_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK)

modlintlib:	$(MODLINTLIB_DEPS) lint32

lint:		$(LINT_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/sparc/Makefile.targ

#
#	Defines for local commands.
#
WARLOCK		= warlock
WLCC		= wlcc
TOUCH		= touch
TEST		= test

#
#	Warlock targets
#
SBP2_FILES = $(SBP2_OBJS:%.o= -l ../sbp2/%.ll)
SD_FILES   = $(SD_OBJS:%.o=../sd/%.ll)
SCSI_FILES = $(SCSI_OBJS:%.o= -l ../scsi/%.ll)
CMLB_FILES = $(CMLB_OBJS:%.o=-l ../cmlb/%.ll)

warlock: $(WARLOCK_OK)

$(WARLOCK_OK): $(WARLOCK_OUT) sbp2.files warlock_ddi.files \
	$(WLCMD_DIR)/scsa1394.wlcmd sd.files scsi.files cmlb.files
	$(WARLOCK) -c $(WLCMD_DIR)/scsa1394.wlcmd $(WARLOCK_OUT) $(SD_FILES) \
		$(SCSI_FILES) \
		$(CMLB_FILES) \
		$(SBP2_FILES) \
		-l ../warlock/ddi_dki_impl.ll
	$(TOUCH) $@

%.ll: $(UTSBASE)/common/io/1394/targets/scsa1394/%.c
	$(WLCC) $(CPPFLAGS) -DNPROBE -DDEBUG -o $@ $<

sbp2.files:
	@cd ../sbp2; pwd; $(MAKE) warlock

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock

sd.files:
	@cd ../sd; pwd; $(MAKE) warlock_alone

scsi.files:
	@cd ../scsi; pwd; $(MAKE) warlock

cmlb.files:
	@cd ../cmlb; pwd; $(MAKE) warlock


