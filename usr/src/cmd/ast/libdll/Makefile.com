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
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.

SHELL= /usr/bin/ksh93

LIBRARY= libdll.a
VERS= .1

include ../Makefile.defs

OBJECTS += $(LIBOBJS)

include $(SRC)/lib/Makefile.lib
include ../../Makefile.ast

MAPFILES= ../mapfile-vers

LIBS= $(DYNLIB)

LDLIBS += -last -lc

# We use "=" here since using $(CPPFLAGS.master) is very tricky in our
# case - it MUST come as the last element but future changes in -D options
# may then cause silent breakage in the AST sources because the last -D
# option specified overrides previous -D options so we prefer the current
# way to explicitly list each single flag.
# Notes:
#   - "-D_BLD_DLL" comes from ${mam_cc_DLL} in Mamfile
CPPFLAGS= \
	$(DTEXTDOM) $(DTS_ERRNO) \
	$(DLLPLATFORMCPPFLAGS) \
	-Iast -I. \
	-I$(ROOT)/usr/include/ast \
	-I$(ROOT)/usr/include \
	'-DCONF_LIBSUFFIX=".so"' \
	'-DCONF_LIBPREFIX="lib"' \
	-D_PACKAGE_ast \
	-D_BLD_DLL \
	-D_BLD_dll

CFLAGS += $(ASTCFLAGS)
CFLAGS64 += $(ASTCFLAGS64)

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= $(CNOWARN_UNINIT)

# needs work
SMOFF += all_func_returns,strcpy_overflow

.KEEP_STATE:

all: install_h .WAIT $(LIBS)

include $(SRC)/lib/Makefile.targ

pics/%.o: $(ASTSRC)/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<
	$(POST_PROCESS_O)

######################################################################
# Header file generation

$(HEADERGEN:%=ast/%): $(FEATURES:%=FEATURE/%)
	$(MKDIR) -p $(@D)
	src=`echo $(@F:%.h=%) | sed 's/^ast_//'`; \
	    [[ $$src = dlldefs ]] && src=dll; \
	    $(AST_PROTO) FEATURE/$$src > $@
	$(POST_PROCESS_AST) $@

install_h: $(HEADERGEN:%=ast/%)

CLOBBERFILES += ast/*

_feature: FRC
	$(MAKE) -f Makefile.iffe generate

include ../../Makefile.astmsg

FRC:
