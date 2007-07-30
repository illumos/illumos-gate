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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of the wrsm driver kernel module.
#
#	sun4u implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= wrsm 
OBJECTS		= $(WRSM_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(WRSM_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_SERENGETI_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/sun4u/io/wrsm

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/serengeti/Makefile.serengeti

#
#	Starcat platform directory names
#
ROOT_STARCAT_DIR	= $(ROOT_PLAT_DIR)/SUNW,Sun-Fire-15000
ROOT_STARCAT_MOD_DIR	= $(ROOT_STARCAT_DIR)/kernel
ROOT_STARCAT_DRV_DIR_32 = $(ROOT_STARCAT_MOD_DIR)/drv
ROOT_STARCAT_DRV_DIR_64 = $(ROOT_STARCAT_MOD_DIR)/drv/$(SUBDIR64)
ROOT_STARCAT_DRV_DIR	= $(ROOT_STARCAT_DRV_DIR_$(CLASS))


ROOT_CONFFILE	= $(ROOT_SERENGETI_DRV_DIR_32)/$(MODULE).conf
STARCAT_CONFFILE = $(ROOT_STARCAT_DRV_DIR_32)/$(MODULE).conf
STARCAT_DRV_LINK = $(ROOT_STARCAT_DRV_DIR)/$(MODULE)

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE) \
			$(STARCAT_CONFFILE) $(STARCAT_DRV_LINK)

WRSM_OFFSETS	= $(UTSBASE)/sun4u/io/wrsm/wrsm_offsets.in
WRSM_OFFSETS_H	= $(OBJS_DIR)/wrsm_offsets.h

#
# Include path for rsm header files
#
INC_PATH += -I$(CODEMGR_WS)/usr/src/uts/common

#
# Path to netdb.h
#
INC_PATH += -I$(CODEMGR_WS)/usr/src/head

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE)

#
# module dependencies
#
LDFLAGS += -dy -Nmisc/wrsmplat -Nmisc/rsmops


#
# Turn on doubleword alignment for 64 bit registers
#

CFLAGS += -dalign $(WRSM_FLAGS)
ASFLAGS += $(WRSM_FLAGS)

ALL_DEFS += $(WRSM_WORKAROUND_DEFS)

LINT_DEFS += -DRSMPI -DWRSM_MB -DFAKEREGS -DRSMAPI

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
# Special rules for generating assym.h for inclusion in assembly files
#
$(DSF_DIR)/$(OBJS_DIR)/assym.h: FRC
	@cd $(DSF_DIR); $(MAKE) all.targ

AS_INC_PATH	+= -I$(OBJS_DIR)

WRSM_DEPS	+=	wrsm_trap.o

WRSM_DEPS	+=	wrsm_copy.o

CLEANFILES	+= $(WRSM_OFFSETS_H) $(WRSM_OFFSETS_OUT)

$(WRSM_DEPS:%=$(OBJS_DIR)/%):	$(WRSM_OFFSETS_H)

$(WRSM_OFFSETS_H): $(WRSM_OFFSETS)
	$(OFFSETS_CREATE) <$(WRSM_OFFSETS) >$@

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/Makefile.targ

$(ROOT_SERENGETI_DIR): $(ROOT_PLAT_DIR)
	-$(INS.dir.root.sys)

$(ROOT_SERENGETI_MOD_DIR): $(ROOT_SERENGETI_DIR)
	-$(INS.dir.root.sys)

$(ROOT_SERENGETI_DRV_DIR_32): $(ROOT_SERENGETI_MOD_DIR)
	-$(INS.dir.root.sys)

$(ROOT_SERENGETI_DRV_DIR): $(ROOT_SERENGETI_DRV_DIR_32)
	-$(INS.dir.root.sys)

$(ROOT_SERENGETI_DRV_DIR)/%: $(OBJS_DIR)/% $(ROOT_SERENGETI_DRV_DIR)
	$(INS.file)

$(ROOT_STARCAT_DIR): $(ROOT_PLAT_DIR)
	-$(INS.dir.root.sys)

$(ROOT_STARCAT_MOD_DIR): $(ROOT_STARCAT_DIR)
	-$(INS.dir.root.sys)

$(ROOT_STARCAT_DRV_DIR_32): $(ROOT_STARCAT_MOD_DIR)
	-$(INS.dir.root.sys)

$(ROOT_STARCAT_DRV_DIR): $(ROOT_STARCAT_DRV_DIR_32)
	-$(INS.dir.root.sys)

$(ROOT_STARCAT_DRV_DIR)/%: $(OBJS_DIR)/% $(ROOT_STARCAT_DRV_DIR)
	$(INS.file)

$(STARCAT_CONFFILE): $(SRC_CONFFILE) $(STARCAT_CONFFILE:%/$(CONFFILE)=%) $(ROOT_STARCAT_DRV_DIR)
	$(INS.conffile)

$(STARCAT_DRV_LINK): $(ROOTMODULE) $(ROOT_STARCAT_DRV_DIR)
	$(RM) -r $@; $(LN) $(ROOTMODULE) $@
