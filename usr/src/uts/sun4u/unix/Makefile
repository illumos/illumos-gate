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
# Copyright 2019 Joyent, Inc.
#

#
#	This makefile drives the production of unix (and unix.o).
#
#	sun4u implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
UNIX		= unix
OBJECTS		= $(SPECIAL_OBJS:%=$(OBJS_DIR)/%) \
		  $(CORE_OBJS:%=$(OBJS_DIR)/%) \
		  $(MACH_NOT_YET_KMODS:%=$(OBJS_DIR)/%)

KRTLD_MAPFILE	= $(UTSBASE)/sparc/krtld/mapfile
KRTLD_OBJECTS	= $(KRTLD_OBJS:%=$(OBJS_DIR)/%)
KRTLD_O		= $(OBJS_DIR)/krtld.o

ROOTMODULE	= $(ROOT_PSM_KERN_DIR)/$(UNIX)
UNIX32_LINK	= $(ROOT_PSM_KERN_DIR_32)/$(UNIX)
UNIX_BIN	= $(OBJS_DIR)/$(UNIX)
#UNIX_GLOM	= $(OBJS_DIR)/unix.glom

LIBS		= $(GENLIB) $(PLATLIB) $(CPULIB)

GENUNIX		= genunix
GENUNIX_DIR	= ../$(GENUNIX)
GENOPTS		= -L $(GENUNIX_DIR)/$(OBJS_DIR) -l $(GENUNIX)

CPU_DIR		= .
CPUOPTS		= -L $(CPU_DIR)/$(OBJS_DIR) -l $(CPUNAME)

PLAT_DIR	= ../platmod
PLATOPTS	= -L $(PLAT_DIR)/$(OBJS_DIR) -l $(PLATMOD)

LIBOPTS		= $(GENOPTS) $(PLATOPTS) $(CPUOPTS)

CTFEXTRAOBJS	= $(OBJS_DIR)/vers.o

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/Makefile.sun4u

#
#	Define targets
#
ALL_TARGET	= $(UNIX_BIN)
INSTALL_TARGET	= $(UNIX_BIN) $(ROOTMODULE) $(UNIX32_LINK)

#
#	This is UNIX_DIR. Use a short path.
#
UNIX_DIR	= .

#
#	Overrides
#
CLEANFILES	+= $(UNIX_O) $(MODSTUBS_O) $(KRTLD_O) $(KRTLD_OBJECTS) \
		   $(OBJS_DIR)/vers.c $(OBJS_DIR)/vers.o \
		   $(CPU_OBJ) $(CPULIB) \
		   $(DTRACESTUBS_O) $(DTRACESTUBS)

CLOBBERFILES	= $(CLEANFILES) $(UNIX_BIN)

#
# For now, disable these warnings; maintainers should endeavor
# to investigate and remove these for maximum coverage.
# Please do not carry these forward to new Makefiles.
#
CFLAGS		+= $(CCVERBOSE)
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-char-subscripts
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-clobbered
CERRWARN	+= -_gcc=-Wno-empty-body
CERRWARN	+= -_gcc=-Wno-unused-value
CERRWARN	+= -_gcc=-Wno-switch

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)


$(UNIX_BIN):	$(UNIX_O) $(KRTLD_O) $(MODSTUBS_O) $(UNIX_MAPFILE) $(LIBS) \
		$(DTRACESTUBS)
	$(LD) -dy -b -o $@ -e _start -M $(UNIX_MAPFILE) \
	    $(UNIX_O) $(KRTLD_O) $(MODSTUBS_O) $(LIBOPTS) $(DTRACESTUBS)
	$(CTFMERGE_UNIQUIFY_AGAINST_GENUNIX)
	$(POST_PROCESS)

$(UNIX32_LINK):	$(ROOT_PSM_KERN_DIR_32) $(UNIX_BIN)
	-$(RM) $@; ln -s $(SUBDIR64)/$(UNIX) $@

symcheck:	$(UNIX_O) $(KRTLD_O) $(MODSTUBS_O) $(LIBS)
	$(LD) -dy -b -o $(SYM_MOD) -M $(UNIX_MAPFILE) \
	$(UNIX_O) $(KRTLD_O) $(MODSTUBS_O) $(LIBOPTS) $(DTRACESTUBS)

$(UNIX_O):	$(OBJECTS) $(OBJS_DIR)/vers.o
	$(LD) -r -o $@ $(OBJECTS) $(OBJS_DIR)/vers.o

$(KRTLD_O):	$(KRTLD_OBJECTS)
	$(LD) -r -o $@ -M$(KRTLD_MAPFILE) $(KRTLD_OBJECTS)

#
#	CPU_OBJ now comprises of 2 object files which come from sun4 common
#	and from architecture dependent code.  OBJS_DIR is prepended where
#	CPU_OBJ is defined to allow for building multiple CPU_OBJ's
#
$(CPULIB):	$(CPU_OBJ)
	$(BUILD.SO) $(CPU_OBJ)

$(PLATLIB):
	?@(cd $(PLAT_DIR); pwd; $(MAKE) all.targ)
	?@pwd

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/Makefile.targ

