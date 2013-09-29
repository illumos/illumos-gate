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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2012, Joyent, Inc.  All rights reserved.
#

#
# The build process for libumem is sightly different from that used by other
# libraries, because libumem must be built in two flavors - as a standalone
# for use by kmdb and as a normal library.  We use $(CURTYPE) to indicate the
# current flavor being built.
#

LIBRARY = libumem.a
STANDLIBRARY = libstandumem.so
VERS = .1

# By default, we build the shared library.  Construction of the standalone
# is specifically requested by architecture-specific Makefiles.
TYPES = library
CURTYPE = library

# This would be much prettier if a) Makefile.lib didn't reqire both $(SRCS) and
# $(OBJECTS) to be set or b) make gave us a nice way to do basename in pattern
# replacement definitions.

# Files specific to the library version of libumem
OBJECTS_library = \
	init_lib.o \
	umem_agent_support.o \
	umem_fail.o \
	umem_fork.o \
	umem_update_thread.o \
	vmem_mmap.o \
	vmem_sbrk.o

SRCS_library = $(OBJECTS_library:%.o=../common/%.c)

# Files specific to the standalone version of libumem
OBJECTS_standalone = \
	init_stand.o \
	stub_stand.o \
	vmem_stand.o

SRCS_standalone = $(OBJECTS_standalone:%.o=../common/%.c)

# Architecture-dependent files common to both versions of libumem
OBJECTS_common_isadep = \
	asm_subr.o \
	umem_genasm.o	

SRCS_common_isadep = \
	$(ISASRCDIR)/asm_subr.s \
	$(ISASRCDIR)/umem_genasm.c

# Architecture-independent files common to both versions  of libumem
OBJECTS_common_common = \
	envvar.o \
	getpcstack.o \
	malloc.o \
	misc.o \
	vmem_base.o \
	umem.o \
	vmem.o

SRCS_common_common = $(OBJECTS_common_common:%.o=../common/%.c)

OBJECTS = \
	$(OBJECTS_$(CURTYPE)) \
	$(OBJECTS_common_isadep) \
	$(OBJECTS_common_common)

include ../../Makefile.lib
include ../../Makefile.rootfs

SRCS = \
	$(SRCS_$(CURTYPE)) \
	$(SRCS_common_isadep) \
	$(SRCS_common_common)

SRCDIR = ../common

#
# Used to verify that the standalone doesn't have any unexpected external
# dependencies.
#
LINKTEST_OBJ = objs/linktest_stand.o

CLOBBERFILES_standalone = $(LINKTEST_OBJ)
CLOBBERFILES += $(CLOBBERFILES_$(CURTYPE))

LIBS_standalone = $(STANDLIBRARY)
LIBS_library = $(DYNLIB) $(LINTLIB)
LIBS =	$(LIBS_$(CURTYPE))

MAPFILE_SUPPLEMENTAL_standalone = ../common/stand_mapfile
MAPFILE_SUPPLEMENTAL = $(MAPFILE_SUPPLEMENTAL_$(CURTYPE))

LDLIBS +=	-lc

LDFLAGS_standalone = $(ZNOVERSION) $(BREDUCE) -M../common/mapfile-vers \
	-M$(MAPFILE_SUPPLEMENTAL) -dy -r
LDFLAGS = $(LDFLAGS_$(CURTYPE))

ASFLAGS_standalone = -DUMEM_STANDALONE
ASFLAGS_library =
ASFLAGS += -P $(ASFLAGS_$(CURTYPE)) -D_ASM

CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-uninitialized

$(LINTLIB) := SRCS = ../common/$(LINTSRC)

# We want the thread-specific errno in the library, but we don't want it in
# the standalone.  $(DTS_ERRNO) is designed to add -D_TS_ERRNO to $(CPPFLAGS),
# in order to enable this feature.  Conveniently, -D_REENTRANT does the same
# thing.  As such, we null out $(DTS_ERRNO) to ensure that the standalone
# doesn't get it.
DTS_ERRNO=

# We need to rename some standard functions so we can easily implement them
# in consumers.
STAND_RENAMED_FUNCS= \
	atomic_add_64 \
	atomic_add_32_nv \
	atomic_swap_64 \
	snprintf \
	vsnprintf

CPPFLAGS_standalone = -DUMEM_STANDALONE $(STAND_RENAMED_FUNCS:%=-D%=umem_%)
CPPFLAGS_library = -D_REENTRANT
CPPFLAGS +=	-I../common -I../../common/inc $(CPPFLAGS_$(CURTYPE))

CFLAGS_standalone = $(STAND_FLAGS_32)
CFLAGS_common =
CFLAGS += $(CFLAGS_$(CURTYPE)) $(CFLAGS_common)

CFLAGS64_standalone = $(STAND_FLAGS_64)
CFLAGS64 += $(CCVERBOSE) $(CFLAGS64_$(CURTYPE)) $(CFLAGS64_common)

INSTALL_DEPS_library =		$(ROOTLINKS) $(ROOTLINT) $(ROOTLIBS)

#
# turn off ptr-cast warnings, since we do them all the time
#
LINTFLAGS +=	-erroff=E_BAD_PTR_CAST_ALIGN
LINTFLAGS64 +=	-erroff=E_BAD_PTR_CAST_ALIGN

DYNFLAGS +=     $(ZINTERPOSE)

.KEEP_STATE:
