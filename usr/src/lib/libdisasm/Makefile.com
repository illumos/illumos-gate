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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
#

#
# The build process for libdisasm is sightly different from that used by other
# libraries, because libdisasm must be built in two flavors - as a standalone
# for use by kmdb and as a normal library.  We use $(CURTYPE) to indicate the
# current flavor being built.
#

LIBRARY=	libdisasm.a
STANDLIBRARY=	libstanddisasm.so
VERS=		.1

# By default, we build the shared library.  Construction of the standalone
# is specifically requested by architecture-specific Makefiles.
TYPES=		library
CURTYPE=	library

COMDIR=		$(SRC)/lib/libdisasm/common

#
# Architecture-independent files
#
SRCS_common=		$(COMDIR)/libdisasm.c
OBJECTS_common=		libdisasm.o

#
# Architecture-dependent disassembly files
#
SRCS_i386=		$(COMDIR)/dis_i386.c \
			$(SRC)/common/dis/i386/dis_tables.c
SRCS_sparc=		$(COMDIR)/dis_sparc.c \
			$(COMDIR)/dis_sparc_fmt.c \
			$(COMDIR)/dis_sparc_instr.c

OBJECTS_i386=		dis_i386.o \
			dis_tables.o
OBJECTS_sparc=		dis_sparc.o \
			dis_sparc_fmt.o \
			dis_sparc_instr.o

#
# We build the regular shared library with support for all architectures.
# The standalone version should only contain code for the native
# architecture to reduce the memory footprint of kmdb.
#
OBJECTS_library=	$(OBJECTS_common) \
			$(OBJECTS_i386) \
			$(OBJECTS_sparc)
OBJECTS_standalone=	$(OBJECTS_common) \
			$(OBJECTS_$(MACH))
OBJECTS=		$(OBJECTS_$(CURTYPE))

include $(SRC)/lib/Makefile.lib

SRCS_library=		$(SRCS_common) \
			$(SRCS_i386) \
			$(SRCS_sparc)
SRCS_standalone=	$(SRCS_common) \
			$(SRCS_$(MACH))
SRCS=			$(SRCS_$(CURTYPE))

#
# Used to verify that the standalone doesn't have any unexpected external
# dependencies.
#
LINKTEST_OBJ = objs/linktest_stand.o

CLOBBERFILES_standalone = $(LINKTEST_OBJ)
CLOBBERFILES += $(CLOBBERFILES_$(CURTYPE))

LIBS_standalone	= $(STANDLIBRARY)
LIBS_library = $(DYNLIB) $(LINTLIB)
LIBS = $(LIBS_$(CURTYPE))

MAPFILES =	$(COMDIR)/mapfile-vers

LDLIBS +=	-lc

LDFLAGS_standalone = $(ZNOVERSION) $(BREDUCE) -dy -r
LDFLAGS = $(LDFLAGS_$(CURTYPE))

ASFLAGS_standalone = -DDIS_STANDALONE
ASFLAGS_library =
ASFLAGS += -P $(ASFLAGS_$(CURTYPE)) -D_ASM

$(LINTLIB) := SRCS = $(COMDIR)/$(LINTSRC)

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized

# We want the thread-specific errno in the library, but we don't want it in
# the standalone.  $(DTS_ERRNO) is designed to add -D_TS_ERRNO to $(CPPFLAGS),
# in order to enable this feature.  Conveniently, -D_REENTRANT does the same
# thing.  As such, we null out $(DTS_ERRNO) to ensure that the standalone
# doesn't get it.
DTS_ERRNO=

CPPFLAGS_standalone = -DDIS_STANDALONE -I$(SRC)/cmd/mdb/common
CPPFLAGS_library = -D_REENTRANT
CPPFLAGS +=	-I$(COMDIR) $(CPPFLAGS_$(CURTYPE))

# For the x86 disassembler we have to include sources from usr/src/common
CPPFLAGS += -I$(SRC)/common/dis/i386 -DDIS_TEXT

CFLAGS_standalone = $(STAND_FLAGS_32)
CFLAGS_common =
CFLAGS += $(CFLAGS_$(CURTYPE)) $(CFLAGS_common)

CFLAGS64_standalone = $(STAND_FLAGS_64)
CFLAGS64 += $(CCVERBOSE) $(CFLAGS64_$(CURTYPE)) $(CFLAGS64_common)

C99MODE = $(C99_ENABLE)

DYNFLAGS +=     $(ZINTERPOSE)

.KEEP_STATE:
