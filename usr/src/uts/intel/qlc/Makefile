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
# This makefile drives the production of qlc driver kernel module.
#
# Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= qlc
OBJECTS		= $(QLC_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(QLC_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/fibre-channel/fca/qlc

#
#	Include common rules.
#
include $(UTSBASE)/Makefile.uts
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(CONFMOD) $(ITUMOD)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	header file directories
#
INC_PATH	+= -I$(ROOT)/usr/include
INC_PATH	+= -I$(UTSBASE)/common/sys/fibre-channel
INC_PATH	+= -I$(UTSBASE)/common/sys/fibre-channel/ulp
INC_PATH	+= -I$(UTSBASE)/common/sys/fibre-channel/fca/qlc
INC_PATH	+= -I$(UTSBASE)/common/sys/fibre-channel/impl

LDFLAGS		+= -dy -Nmisc/fctl

#
#	Lint tags
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED

FWTABLE          = ql_fw_table.c
FWIMAGES         = 2200
FWIMAGES        += 2300
FWIMAGES        += 2400
FWIMAGES        += 2500
FWIMAGES        += 6322
FWIMAGES        += 8100

FWMODULES        = $(FWIMAGES:%=$(MODULE)_fw_%)
FWMODULES_SRC    = $(FWIMAGES:%=$(SRC)/uts/common/io/fibre-channel/fca/qlc/ql_fw_%.c)

CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-parentheses

#
#	Default build targets.
#
.KEEP_STATE:

all:		$(SRC)/uts/common/io/fibre-channel/fca/qlc/ql_fw_table.c $(ALL_DEPS)

def:		$(SRC)/uts/common/io/fibre-channel/fca/qlc/ql_fw_table.c $(DEF_DEPS)

clean:		$(SRC)/uts/common/io/fibre-channel/fca/qlc/ql_fw_table.c $(CLEAN_DEPS)

clobber:	$(SRC)/uts/common/io/fibre-channel/fca/qlc/ql_fw_table.c $(CLOBBER_DEPS)

lint:		$(SRC)/uts/common/io/fibre-channel/fca/qlc/ql_fw_table.c $(LINT_DEPS)

modlintlib:	$(SRC)/uts/common/io/fibre-channel/fca/qlc/ql_fw_table.c $(MODLINTLIB_DEPS)

clean.lint:	$(SRC)/uts/common/io/fibre-channel/fca/qlc/ql_fw_table.c $(CLEAN_LINT_DEPS)

install:	$(SRC)/uts/common/io/fibre-channel/fca/qlc/ql_fw_table.c $(INSTALL_DEPS)

$(SRC)/uts/common/io/fibre-channel/fca/qlc/ql_fw_table.c: $(FWMODULES_SRC)
	/usr/bin/rm -f $@
	echo '#include <ql_apps.h>'             >> $@
	echo '#include <ql_api.h>'              >> $@
	echo 'struct fw_table fw_table[] = {'   >> $@
	grep FW_VERSION_STRING $(FWMODULES_SRC) |\
	grep '#define'                          |\
	sed 's/[0-9]"/& },/'                    |\
	sed 's/.*ql_fw_/{ 0x/'                  |\
	sed 's/.c:#define/,/'                   |\
	sed 's/FW_VERSION_STRING//'             >> $@
	echo '{ 0, NULL }'                      >> $@
	echo '};'                               >> $@

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
