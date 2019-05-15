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
# Copyright 2019 Joyent, Inc.
#

#
# VMware Ethernet Adapter b module
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..
UTSCLOSED = ../../../../closed/uts

#
#       Define the module and object file sets.
#
MODULE		= vmxnet
#
ROOTMODULE      = $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/intel/io/vmxnet

#
#       Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
# The list of object files is defined here, rather than in Makefile.files,
# because the "$(CLOSED_BUILD)" macro has not been defined at the time
# Makefile.files is processed.
#
VMXNET_OBJS += vmxnet.o

OBJECTS		= $(VMXNET_OBJS:%=$(OBJS_DIR)/%)
LINTS           = $(VMXNET_OBJS:%.o=$(LINTS_DIR)/%.ln)

#
#       Define targets
#
ALL_TARGET      = $(BINARY) $(SRC_CONFFILE)
LINT_TARGET     = $(LINT_MODULE).lint
INSTALL_TARGET  = $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

CPPFLAGS +=  -I$(UTSBASE)/i86pc
LDFLAGS += -dy -N misc/gld

# needs work
SMOFF += all_func_returns

#
#       Default build targets.
#
.KEEP_STATE:

def:            $(DEF_DEPS)

all:            $(ALL_DEPS)

clean:          $(CLEAN_DEPS)

clobber:        $(CLOBBER_DEPS)

#
# Intentionally don't build lint libraries to minimize divergence with
# the upstream source.
#
lint:
modlintlib:
clean.lint:

install:        $(INSTALL_DEPS)

#
#       Include common targets.
#
include ../Makefile.targ
