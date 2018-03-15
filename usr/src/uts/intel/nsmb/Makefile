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
# uts/intel/nsmb/Makefile
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	intel architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= nsmb
OBJECTS		= $(NSMB_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(NSMB_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(USR_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/fs/smbclnt/netsmb
OFFSETS_SRC	= $(CONF_SRCDIR)/offsets.in
IOC_CHECK_H	= $(OBJS_DIR)/ioc_check.h

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(ALL_TARGET_$(OBJS_DIR))
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(INSTALL_TARGET_$(OBJS_DIR))

#
#	Overrides.
#
#	We need some unusual overrides here so we'll
#	build ioc_check.h for both 32-bit/64-bit,
#	but only build 64-bit binaries.
#

# Build 32-bit also...
DEF_BUILDS	= $(DEF_BUILDS64) $(DEF_BUILDS32)
ALL_BUILDS	= $(ALL_BUILDS64) $(ALL_BUILDS32)
# ... but don't build any 32-bit objects
ALL_TARGET_debug32	= $(IOC_CHECK_H)
ALL_TARGET_debug64	= $(BINARY) $(SRC_CONFILE)
ALL_TARGET_obj32	= $(IOC_CHECK_H)
ALL_TARGET_obj64	= $(BINARY) $(SRC_CONFILE)
# ... and remove -xcg92 (not supported by cw)
CFLAGS_32=
# ... same deal for install targets
INSTALL_TARGET_debug32	= $(IOC_CHECK_H)
INSTALL_TARGET_debug64	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)
INSTALL_TARGET_obj32	= $(IOC_CHECK_H)
INSTALL_TARGET_obj64	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
# Now the normal overrides...
#
MODSTUBS_DIR	= $(OBJS_DIR)
$(MODSTUBS_O)	:= AS_CPPFLAGS += -DNSMB_MODULE
CLEANFILES	+= $(MODSTUBS_O) $(IOC_CHECK_H)
CERRWARN	+= -erroff=E_STATEMENT_NOT_REACHED
INC_PATH	+= -I$(UTSBASE)/common/fs/smbclnt
LDFLAGS         += -dy -Ncrypto/md4 -Ncrypto/md5 -Nmisc/tlimod

# Until CR 4994570 is fixed...
LINTTAGS	+= -erroff=E_BAD_FORMAT_ARG_TYPE2

# The mb_put/md_get functions are intentionally used with and without
# return value checks, so filter those out like LGREP.2 does.
LGREP.nsmb =	egrep -v ' ignored: (mb_init|mb_put|md_get)'
LTAIL	+=	2>&1 | $(LGREP.2) | $(LGREP.nsmb) || true

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
# Create ioc_check.h and compare with the saved
# ioc_check.ref to ensure 32/64-bit invariance.
#
$(OBJECTS) : $(IOC_CHECK_H)
$(IOC_CHECK_H): $(OFFSETS_SRC)
	$(OFFSETS_CREATE) <$(OFFSETS_SRC) >$@.tmp
	cmp -s ioc_check.ref $@.tmp && \
	  mv -f $@.tmp $@

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
