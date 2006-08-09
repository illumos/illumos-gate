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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY = wrsm.a
VERS = .1
OBJECTS = librsmwrsm.o wrsmlib.o

include ../../Makefile.lib

# librsm searches for plug-in libraries in the directory
# /usr/platform/`uname -i`/lib/rsmlib[/sparcv9]
ROOTLIBDIR = $(ROOT)/usr/platform/SUNW,Sun-Fire/lib/rsmlib
ROOTLIBDIR64 = $(ROOTLIBDIR)/$(MACH64)

# wrsm supports both Sun-Fire and Sun-Fire-15K, so create a
# symlink from Sun-Fire-15K to Sun-Fire.

# sparc links
RSMLIBSUNFIRE15K = $(ROOT)/usr/platform/SUNW,Sun-Fire-15000/lib/rsmlib
RSMLINKSUNFIRE15K = $(RSMLIBSUNFIRE15K)/$(LIBLINKS)
RSMLINKREL = ../../../SUNW,Sun-Fire/lib/rsmlib/$(LIBLINKS)$(VERS)
RSMLINKS= $(RSMLINKSUNFIRE15K)
# sparcv9 links
RSMLIBSUNFIRE15K64 = $(RSMLIBSUNFIRE15K)/$(MACH64)
RSMLINKSUNFIRE15K64 = $(RSMLIBSUNFIRE15K64)/$(LIBLINKS)
RSMLINKREL64 = ../../../../SUNW,Sun-Fire/lib/rsmlib/$(MACH64)/$(LIBLINKS)$(VERS)
RSMLINKS64= $(RSMLINKSUNFIRE15K64)

# There should be a mapfile here
MAPFILES =

LIBS = $(DYNLIB)
SRCS = $(SRCDIR)/librsmwrsm.c $(SRCDIR)/wrsmlib.s
LDLIBS += -lc

CFLAGS += $(CCVERBOSE)
CPPFLAGS += -I$(ROOT)/usr/platform/sun4u/include -D_REENTRANT
AS_CPPFLAGS += -I$(ROOT)/usr/platform/sun4u/include 
ASFLAGS += -D_ASM -P -xarch=v8plusa -K pic
sparcv9_XARCH = -xarch=v9a

.KEEP_STATE:

all: $(LIBS)

# Only do lint for sparc platform
lint: $(MACH)_lint

i386_lint:

sparc_lint: lintcheck

# Rule for compiling .s file
pics/wrsmlib.o: $(SRCDIR)/wrsmlib.s
	$(COMPILE.s) -o $@ $(SRCDIR)/wrsmlib.s
	$(POST_PROCESS_O)

# Rules for creating RSMAPI-defined sym links
$(ROOTLIBDIR) $(ROOTLIBDIR64) $(RSMLIBSUNFIRE15K) $(RSMLIBSUNFIRE15K64):
	$(INS.dir.root.bin)

$(RSMLINKSUNFIRE15K): $(RSMLIBSUNFIRE15K) $(LIBS)
	$(RM) $@; $(SYMLINK) $(RSMLINKREL) $@

$(RSMLINKSUNFIRE15K64): $(RSMLIBSUNFIRE15K) $(RSMLIBSUNFIRE15K64) $(LIBS)
	$(RM) $@; $(SYMLINK) $(RSMLINKREL64) $@

include ../../Makefile.targ
include ../../../Makefile.psm
