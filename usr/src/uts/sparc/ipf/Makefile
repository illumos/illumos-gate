#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# uts/sparc/ipf/Makefile
#
#
#	This makefile drives the production of the ipf driver 
#	kernel module.
#
#	sparc architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= ipf
OBJECTS		= $(IPF_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(IPF_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(USR_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/inet/ipf

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
# lint pass one enforcement and OS version
#
MINOR=    echo $(RELEASE) | cut -d. -f2
CFLAGS += $(CCVERBOSE)
CPPFLAGS += -DIPFILTER_LKM -DIPFILTER_LOG -DIPFILTER_LOOKUP 
CPPFLAGS += -DSUNDDI -DSOLARIS2=$(MINOR:sh) -DIRE_ILL_CN
LDFLAGS += -dy -Ndrv/ip -Ndrv/pfil -Nmisc/md5

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
include $(UTSBASE)/sparc/Makefile.targ
