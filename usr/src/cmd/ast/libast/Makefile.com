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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2019, Joyent, Inc.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.

SHELL= /usr/bin/ksh93

LIBRARY= libast.a
VERS= .1

include ../Makefile.defs

OBJECTS += $(LIBOBJS)

include $(SRC)/lib/Makefile.lib
include ../../Makefile.ast

MAPFILES= ../mapfile-vers

LIBS= $(DYNLIB)
LDLIBS += -lm -lc -lsocket

# We use "=" here since using $(CPPFLAGS.master) is very tricky in our
# case - it MUST come as the last element but future changes in -D options
# may then cause silent breakage in the AST sources because the last -D
# option specified overrides previous -D options so we prefer the current
# way to explicitly list each single flag.
# Notes:
#   - "-D_BLD_DLL" comes from ${mam_cc_DLL} in Mamfile
#   - Be careful with "-D__OBSOLETE__=xxx". Make sure this is in sync with
#     upstream (see Mamfile) and do not change the |__OBSOLETE__| value
#     without examining the symbols that will be removed, and evaluating
#     whether that breaks compatibility with upstream binaries.
CPPFLAGS= \
	$(DTEXTDOM) $(DTS_ERRNO) \
	$(ASTPLATFORMCPPFLAGS) \
	-Iast -I. \
	-I$(ASTSRC) \
	-I$(ASTSRC)/comp \
	-I$(ASTSRC)/include \
	-I$(ASTSRC)/std \
	-I$(ASTSRC)/dir \
	-I$(ASTSRC)/port \
	-I$(ASTSRC)/sfio \
	-I$(ASTSRC)/misc \
	-I$(ASTSRC)/string \
	-I$(ROOT)/usr/include \
	'-DCONF_LIBSUFFIX=".so"' \
	'-DCONF_LIBPREFIX="lib"' \
	-DERROR_CATALOG=\""libast"\" \
	-D__OBSOLETE__=20120101 \
	-D_BLD_ast \
	-D_PACKAGE_ast \
	-D_BLD_DLL \
	-D_AST_std_malloc=1

CFLAGS += $(ASTCFLAGS)
CFLAGS64 += $(ASTCFLAGS64)

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-char-subscripts
CERRWARN += -_gcc=-Wno-clobbered
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-unused-but-set-variable
CERRWARN += -_gcc=-Wno-unused-but-set-parameter
CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-empty-body
CERRWARN += -_gcc=-Wno-type-limits
CERRWARN += -_gcc=-Wno-address

# It seems, we get false positives with following three files.
# Since this is third party source, silencing this warning seems to be
# reasonable path to take.
pics/path/pathpath.o := CERRWARN += -_gcc10=-Wno-return-local-addr
pics/path/pathpath.o := CERRWARN += -_gcc14=-Wno-return-local-addr
pics/path/pathkey.o := CERRWARN += -_gcc10=-Wno-return-local-addr
pics/path/pathkey.o := CERRWARN += -_gcc14=-Wno-return-local-addr
pics/path/pathprobe.o := CERRWARN += -_gcc10=-Wno-return-local-addr
pics/path/pathprobe.o := CERRWARN += -_gcc14=-Wno-return-local-addr

# The code layout after macro expansion is upsetting gcc 14, silence it.
pics/sfio/sfdisc.o := CERRWARN += -_gcc14=-Wno-misleading-indentation
pics/sfio/sfstack.o := CERRWARN += -_gcc14=-Wno-misleading-indentation

SMATCH= off

.KEEP_STATE:

all: install_h mkpicdirs .WAIT $(LIBS)

mkpicdirs:
	@mkdir -p $(LOBJDIRS:%=pics/%)

include $(SRC)/lib/Makefile.targ

pics/%.o: $(ASTSRC)/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<
	$(POST_PROCESS_O)

######################################################################
# Header file generation

ast/%:= FILEMODE= 0644

# The HEADERGEN headers are generated from the corresponding FEATURE/ file
# with any ast_ prefix removed.
$(HEADERGEN:%=ast/%): $(FEATURES:%=FEATURE/%)
	src=`echo $(@F:%.h=%) | sed 's/^ast_//'`; \
	    $(AST_PROTO) FEATURE/$$src > $@
	$(POST_PROCESS_AST)

ast/prototyped.h: $(AST_TOOLS)/proto
	$(MKDIR) -p $(@D)
	$(AST_TOOLS)/proto -f /dev/null > $@

ast/ast_common.h: ast/prototyped.h
	$(AST_PROTO) FEATURE/common | $(GREP) -v 'define _def_map_' > $@
	$(POST_PROCESS_AST)
	$(CP) $@ .

ast/lc.h: lc.h
	$(AST_PROTO) lc.h > ast/lc.h

ast/%.h: $(ASTSRC)/include/%.h
	$(INS.file)
	$(POST_PROCESS_AST)

ast/%.h: $(ASTSRC)/comp/%.h
	$(INS.file)
	$(POST_PROCESS_AST)

ast/%.h: $(ASTSRC)/cdt/%.h
	$(INS.file)
	$(POST_PROCESS_AST)

ast/%.h: $(ASTSRC)/std/%.h
	$(INS.file)
	$(POST_PROCESS_AST)

ast/ast_namval.h: $(ASTSRC)/include/namval.h
	$(CP) $(ASTSRC)/include/namval.h $@
	$(POST_PROCESS_AST)

CLOBBERFILES += ast_common.h t.c
CLOBBERFILES += ast/*

install_h: ast/prototyped.h ast/ast_common.h ast/lc.h \
	$(HEADERGEN:%=ast/%) $(HEADERSRC:%=ast/%)

.PARALLEL: $(HEADERGEN:%=ast/%) $(HEADERSRC:%=ast/%)

_feature: FRC
	$(MAKE) -f Makefile.iffe generate

include ../../Makefile.astmsg

FRC:
