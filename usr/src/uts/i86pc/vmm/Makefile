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
# Copyright 2013 Pluribus Networks Inc.
# Copyright 2019 Joyent, Inc.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= vmm
OBJECTS		= $(VMM_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(USR_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/i86pc/io/vmm
MAPFILE		= $(UTSBASE)/i86pc/io/vmm/vmm.mapfile

#
#	Include common rules.
#
include $(UTSBASE)/i86pc/Makefile.i86pc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Overrides and additions
#


# 3rd party code
SMOFF += all_func_returns

# needs work
$(OBJS_DIR)/vmm_sol_dev.o := SMOFF += signed_integer_overflow_check

ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)
PRE_INC_PATH	= -I$(COMPAT)/bhyve -I$(COMPAT)/bhyve/amd64 \
	-I$(CONTRIB)/bhyve -I$(CONTRIB)/bhyve/amd64
INC_PATH	+= -I$(UTSBASE)/i86pc/io/vmm -I$(UTSBASE)/i86pc/io/vmm/io
AS_INC_PATH	+= -I$(UTSBASE)/i86pc/io/vmm -I$(OBJS_DIR)

# enable collection of VMM statistics
CFLAGS		+= -DVMM_KEEP_STATS

LDFLAGS         += -N misc/acpica -N misc/pcie -N fs/dev
LDFLAGS         += -M $(MAPFILE)

OFFSETS_VMX	= $(CONF_SRCDIR)/intel/offsets.in
OFFSETS_SVM	= $(CONF_SRCDIR)/amd/offsets.in
ASSYM_VMX	= $(OBJS_DIR)/vmx_assym.h
ASSYM_SVM	= $(OBJS_DIR)/svm_assym.h
ASSYM_H		= $(ASSYM_VMX) $(ASSYM_SVM)

CLEANFILES	+= $(ASSYM_H)

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
include $(UTSBASE)/i86pc/Makefile.targ

$(ASSYM_VMX): $(OFFSETS_VMX) $(GENASSYM)
	$(OFFSETS_CREATE) -I../../i86pc/io/vmm < $(OFFSETS_VMX) >$@
$(ASSYM_SVM): $(OFFSETS_SVM) $(GENASSYM)
	$(OFFSETS_CREATE) -I../../i86pc/io/vmm < $(OFFSETS_SVM) >$@

$(OBJS_DIR)/vmx_support.o:  $(ASSYM_VMX)
$(OBJS_DIR)/svm_support.o:  $(ASSYM_SVM)
