#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2019, Joyent, Inc.
#

#
# uts/intel/bnxe/Makefile
#
#	This makefile drives the production of the bnxe
#	driver kernel module.
#
#	intel architecture dependent
#

#
#	Paths to the base of the uts directory trees
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= bnxe
OBJECTS		= $(BNXE_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
SRCDIR		= $(UTSBASE)/common/io/bnxe
CONF_SRCDIR	= $(SRCDIR)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(CONFMOD)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Driver-specific flags
#	XXX inline bits were originally set to inline
#
CPPFLAGS	+= -DLM_RXPKT_NON_CONTIGUOUS \
		   -DELINK_ENHANCEMENTS \
		   -DELINK_57711E_SUPPORT \
		   -DELINK_DEBUG \
		   -D__inline= \
		   -D_inline= \
		   -D__BASENAME__=\"bnxe\" \
		   -D__SunOS \
		   -D__S11 \
		   -DILLUMOS \
		   -DLITTLE_ENDIAN \
		   -DLITTLE_ENDIAN_HOST \
		   -D__LITTLE_ENDIAN \
		   -I$(SRCDIR)/577xx/include \
		   -I$(SRCDIR)/577xx/drivers/common/ecore \
		   -I$(SRCDIR)/577xx/drivers/common/include \
		   -I$(SRCDIR)/577xx/drivers/common/include/l4 \
		   -I$(SRCDIR)/577xx/drivers/common/include/l5 \
		   -I$(SRCDIR)/577xx/drivers/common/lm/device \
		   -I$(SRCDIR)/577xx/drivers/common/lm/fw \
		   -I$(SRCDIR)/577xx/drivers/common/lm/include \
		   -I$(SRCDIR)/577xx/drivers/common/lm/l4 \
		   -I$(SRCDIR)/577xx/drivers/common/lm/l4/include \
		   -I$(SRCDIR)/577xx/drivers/common/lm/l5 \
		   -I$(SRCDIR)/577xx/drivers/common/lm/l5/include \
		   -I$(SRCDIR)/577xx/hsi/hw/include \
		   -I$(SRCDIR)/577xx/hsi/mcp \
		   -I$(SRCDIR)

LDFLAGS		+= -Ndrv/ip -Nmisc/mac
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-value
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-but-set-variable

# a whole mess
SMATCH=off


#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
