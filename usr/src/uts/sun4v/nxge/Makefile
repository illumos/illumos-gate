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
# uts/sun4v/nxge/Makefile
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
#
#	This makefile drives the production of the N2 NIU
#	10G and SUN 10G/1G Ethernet leaf driver kernel module.
#
#	sun4v implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= nxge
NXGE_OBJECTS =	$(NXGE_OBJS) $(NXGE_NPI_OBJS) $(NXGE_HCALL_OBJS)
OBJECTS		=  $(NXGE_OBJECTS:%=$(OBJS_DIR)/%)
LINTS		= $(NXGE_OBJECTS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_PSM_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/nxge

#
#	Include common rules.
#
include $(UTSBASE)/sun4v/Makefile.sun4v

#
#	Override defaults to build a unique, local modstubs.o.
#
MODSTUBS_DIR	= $(OBJS_DIR)

CLEANFILES	+= $(MODSTUBS_O)

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#
# Turn on doubleword alignment for 64 bit registers
#
CFLAGS	+= -dalign
#
# Include nxge specific header files
#
INC_PATH	+= -I$(UTSBASE)/common/io/nxge/npi
INC_PATH	+= -I$(UTSBASE)/common/sys/nxge
INC_PATH	+= -I$(UTSBASE)/sun4v
#
#
# lint pass one enforcement
#
CFLAGS += -DSOLARIS
# NEMO
#CFLAGS += -DNEMO
#
# Enable the following flags to run mac internal loopback under legion
#CFLAGS += -DLEGION -DAXIS -DAXIS_DEBUG -DAXIS_DEBUG_LB -DSAM_DEBUG
#
# Enable the following flags to run mac internal loopback under AXIS
# (NOTE: LEGION flag can be enabled too)
#CFLAGS += -DAXIS_DEBUG -DAXIS -DAXIS_DEBUG_LB -DSAM_DEBUG -DLEGION
#
# Enable NXGE debug
#CFLAGS += -DNXGE_DEBUG
# Enable NPI debug
#CFLAGS += -DNPI_DEBUG
#CFLAGS += -DNXGE_FM
#CFLAGS += -DUSE_RX_BUFF_ATTR

#CFLAGS += -DNIU_PA_WORKAROUND
#CFLAGS += -DNIU_HV_WORKAROUND
CFLAGS += -DNIU_LP_WORKAROUND

LINTFLAGS += -DSOLARIS
LINTFLAGS += -DNXGE_FM
LINTFLAGS += -DNIU_LP_WORKAROUND
#
# STREAMS, DDI API limitations and other ON header file definitions such as ethernet.h
# force us to turn off these lint checks.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW

CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-type-limits

#
#	Driver depends on mac & IP
#
LDFLAGS		+= -dy -N misc/mac -N drv/ip

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
#	Include common targets.
#
include $(UTSBASE)/sun4v/Makefile.targ
