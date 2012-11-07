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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= nv_sata
OBJECTS		= $(NV_SATA_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(NV_SATA_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR     = $(UTSBASE)/common/io/sata/adapters/nv_sata
WARLOCK_OUT     = $(NV_SATA_OBJS:%.o=%.ll)
WARLOCK_OK      = $(MODULE).ok
WLCMD_DIR	= $(UTSBASE)/common/io/warlock

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Overrides.
#
DEBUG_FLGS	=
DEBUG_DEFS	+= $(DEBUG_FLGS)
CPPFLAGS	+= -DSGPIO_SUPPORT

#
# lint pass one enforcement
#  
CFLAGS += $(CCVERBOSE)

#
# dependency on sata module
#
LDFLAGS += -dy -N misc/sata

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS        += -erroff=E_BAD_PTR_CAST_ALIGN 

CERRWARN	+= -_gcc=-Wno-uninitialized

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK)

clobber:	$(CLOBBER_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ


#
#	Defines for local commands.
#
WARLOCK		= warlock
WLCC		= wlcc
TOUCH		= touch
TEST		= test

NV_SATA_FILES   = $(MODULE).ll
SD_FILES = $(SD_OBJS:%.o=../sd/%.ll)
SATA_FILES = $(SATA_OBJS:%.o=-l ../sata/%.ll)
SCSI_FILES = $(SCSI_OBJS:%.o=-l ../scsi/%.ll)
CMLB_FILES = $(CMLB_OBJS:%.o=-l ../cmlb/%.ll)
 
warlock: $(WARLOCK_OK)


$(WARLOCK_OK): $(WLCMD_DIR)/nv_sata.wlcmd $(WARLOCK_OUT)  warlock_ddi.files \
	sata.files scsi.files sd.files cmlb.files
	$(WARLOCK) -c $(WLCMD_DIR)/nv_sata.wlcmd $(WARLOCK_OUT) \
	$(SD_FILES) \
	$(SCSI_FILES) \
	$(CMLB_FILES) \
        $(SATA_FILES) \
	-l ../warlock/ddi_dki_impl.ll
	$(TOUCH) $@

%.ll: $(UTSBASE)/common/io/sata/adapters/nv_sata/%.c
	$(WLCC) $(CPPFLAGS) -D DEBUG -o $@ $<

sata.files:
	@cd ../sata; pwd; $(MAKE) warlock
 
scsi.files:
	@cd ../scsi; pwd; $(MAKE) warlock

sd.files: 
	@cd ../sd; pwd; $(MAKE) warlock_alone

cmlb.files:
	@cd ../cmlb; pwd; $(MAKE) warlock

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock
