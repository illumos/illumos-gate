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
#

#
# The build process for libdisasm is sightly different from that used by other
# libraries, because libdisasm must be built in two flavors - as a standalone
# for use by kmdb and as a normal library.  We use $(CURTYPE) to indicate the
# current flavor being built.
#
# The SPARC library is built from the closed gate.  This Makefile is shared
# between both environments, so all paths must be absolute.
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
# Architecture-dependent files common to both versions of libdisasm
#
OBJECTS_common_i386 = dis_i386.o dis_tables.o
OBJECTS_common_sparc = dis_sparc.o instr.o dis_sparc_fmt.o

SRCS_common_i386 = $(ISASRCDIR)/dis_i386.c $(SRC)/common/dis/i386/dis_tables.c
SRCS_common_sparc = $(ISASRCDIR)/dis_sparc.c $(ISASRCDIR)/instr.c \
	$(ISASRCDIR)/dis_sparc_fmt.c

#
# Architecture-independent files common to both version of libdisasm
#
OBJECTS_common_common = libdisasm.o
SRC_common_common = $(OBJECTS_common_common:%.o=$(COMDIR)/%.c)


OBJECTS=				\
	$(OBJECTS_common_$(MACH))	\
	$(OBJECTS_common_common)

include $(SRC)/lib/Makefile.lib

SRCS=					\
	$(SRCS_$(CURTYPE))		\
	$(SRCS_common_$(MACH))		\
	$(SRCS_common_common)

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

# We need to rename some standard functions so we can easily implement them 
# in consumers.
STAND_RENAMED_FUNCS= \
	snprintf

CPPFLAGS_standalone = -DDIS_STANDALONE $(STAND_RENAMED_FUNCS:%=-D%=mdb_%) \
	-Dvsnprintf=mdb_iob_vsnprintf -I$(SRC)/cmd/mdb/common
CPPFLAGS_library = -D_REENTRANT
CPPFLAGS +=	-I$(COMDIR) $(CPPFLAGS_$(CURTYPE))

#
# For x86, we have to link to sources in usr/src/common
#
CPPFLAGS_dis_i386 = -I$(SRC)/common/dis/i386 -DDIS_TEXT
CPPFLAGS_dis_sparc =
CPPFLAGS +=	$(CPPFLAGS_dis_$(MACH))

CFLAGS_standalone = $(STAND_FLAGS_32)
CFLAGS_common =
CFLAGS += $(CFLAGS_$(CURTYPE)) $(CFLAGS_common)

CFLAGS64_standalone = $(STAND_FLAGS_64)
CFLAGS64 += $(CCVERBOSE) $(CFLAGS64_$(CURTYPE)) $(CFLAGS64_common)

DYNFLAGS +=     $(ZINTERPOSE)

.KEEP_STATE:
