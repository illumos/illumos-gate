#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

#	This makefile drives the production of the i2c_svc misc module.
#
#	Path to the base of the uts directory tree (usually /usr/src/uts).

UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= i2c_svc
OBJECTS		= $(I2C_SVC_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_PSM_MISC_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/Makefile.sun4u

CFLAGS += $(CCVERBOSE)

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/Makefile.targ
