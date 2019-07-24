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
# Copyright 2019 Joyent, Inc.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= genunix
GENUNIX		= $(OBJS_DIR)/$(MODULE)

OBJECTS		= $(GENUNIX_OBJS:%=$(OBJS_DIR)/%) \
		  $(NOT_YET_KMODS:%=$(OBJS_DIR)/%)

ROOTMODULE	= $(ROOT_KERN_DIR)/$(MODULE)

LIBGEN		= $(OBJS_DIR)/libgenunix.so
LIBSTUBS	= $(GENSTUBS_OBJS:%=$(OBJS_DIR)/%)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(LIBGEN) $(GENUNIX)
INSTALL_TARGET	= $(LIBGEN) $(GENUNIX) $(ROOTMODULE)

#
#	Overrides
#
CLOBBERFILES	+= $(GENUNIX)
CLEANFILES	+= $(LIBSTUBS) $(LIBGEN)
BINARY		=

#
# Non-patch genunix builds merge a version of the ip module called ipctf.  This
# is to ensure that the common network-related types are included in genunix and
# can thus be uniquified out of other modules.  We don't want to do this for
# patch builds, since we can't guarantee that ip and genunix will be in the same
# patch.
#
IPCTF_TARGET	= $(IPCTF)
$(PATCH_BUILD)IPCTF_TARGET =

CPPFLAGS	+= -I$(SRC)/common
CPPFLAGS	+= -I$(SRC)/uts/common/fs/zfs

CPPFLAGS	+= -I$(UTSBASE)/i86pc

CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-value
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-clobbered
CERRWARN	+= -_gcc=-Wno-empty-body

# very hairy
$(OBJS_DIR)/u8_textprep.o := SMATCH=off

# false positives
SMOFF += index_overflow
$(OBJS_DIR)/seg_vn.o := SMOFF += deref_check
$(OBJS_DIR)/ddi_intr_irm.o := SMOFF += deref_check

# need work still
SMOFF += signed,indenting,all_func_returns
$(OBJS_DIR)/clock_highres.o := SMOFF += signed_integer_overflow_check
$(OBJS_DIR)/evchannels.o := SMOFF += allocating_enough_data
$(OBJS_DIR)/klpd.o := SMOFF += cast_assign
$(OBJS_DIR)/lookup.o := SMOFF += strcpy_overflow
$(OBJS_DIR)/process.o := SMOFF += or_vs_and
$(OBJS_DIR)/sunpci.o := SMOFF += deref_check
$(OBJS_DIR)/timers.o := SMOFF += signed_integer_overflow_check

# definitely wrong
$(OBJS_DIR)/acl_common.o := SMOFF += or_vs_and

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

# Due to what seems to be an issue in GCC 4 generated DWARF containing
# symbolic relocations against non-allocatable .debug sections, libgenunix.so
# must be built from a stripped object, thus we create an intermediary
# libgenunix.o we can safely strip.
LIBGENUNIX_O = $(OBJS_DIR)/libgenunix.o
CLEANFILES += $(LIBGENUNIX_O)

$(LIBGENUNIX_O): $(OBJECTS)
	$(LD) -r -o $(OBJS_DIR)/libgenunix.o $(OBJECTS)
	$(STRIP) -x $(OBJS_DIR)/libgenunix.o

$(LIBGEN):	$(LIBGENUNIX_O) $(LIBSTUBS)
	$(BUILD.SO) $(LIBGENUNIX_O) $(LIBSTUBS)

$(IPCTF_TARGET) ipctf_target: FRC
	@cd $(IPDRV_DIR); pwd; $(MAKE) ipctf.$(OBJS_DIR)
	@pwd

$(GENUNIX): $(IPCTF_TARGET) $(OBJECTS)
	$(LD) -r $(LDFLAGS) -o $@ $(OBJECTS)
	$(CTFMERGE_GENUNIX_MERGE)
	$(POST_PROCESS)

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

#
#	Software workarounds for hardware "features".
#
include	$(UTSBASE)/i86pc/Makefile.workarounds

ALL_DEFS += $(WORKAROUND_DEFS)
