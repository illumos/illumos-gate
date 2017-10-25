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
# Copyright 2017 Joyent, Inc.
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
LINTS		= $(VMM_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(USR_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/i86pc/io/vmm

#
#	Include common rules.
#
include $(UTSBASE)/i86pc/Makefile.i86pc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Overrides and additions
#
LINTTAGS	+= -erroff=E_EMPTY_DECLARATION
LINTTAGS	+= -erroff=E_OPERANDS_INCOMPATIBLE_TYPES
LINTTAGS	+= -erroff=E_VOID_CANT_RETURN_VALUE
LINTTAGS	+= -erroff=E_YACC_ERROR
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTTAGS	+= -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTTAGS	+= -erroff=E_BAD_FORMAT_ARG_TYPE2
LINTTAGS	+= -erroff=E_FUNC_ARG_UNUSED
LINTTAGS	+= -erroff=E_FUNC_SET_NOT_USED
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_CONSTANT_CONDITION
LINTTAGS	+= -erroff=E_PTR_TO_VOID_IN_ARITHMETIC
LINTTAGS	+= -erroff=E_CONST_TRUNCATED_BY_ASSIGN
LINTTAGS	+= -erroff=E_NOP_ELSE_STMT
LINTTAGS	+= -erroff=E_FUNC_NO_RET_VAL
LINTTAGS	+= -erroff=E_OLD_STYLE_DECL_OR_BAD_TYPE
LINTTAGS	+= -erroff=E_VAR_USED_BEFORE_SET
LINTTAGS	+= -erroff=E_INTEGER_OVERFLOW_DETECTED
LINTTAGS	+= -erroff=E_STMT_NOT_REACHED
LINTTAGS	+= -erroff=E_FUNC_NO_RET_VAL
LINTTAGS	+= -erroff=E_USELESS_DECLARATION
LINTTAGS	+= -erroff=E_EXPR_NULL_EFFECT
LINTTAGS	+= -erroff=E_CASE_FALLTHRU
LINTTAGS	+= -erroff=E_FUNC_DECL_VAR_ARG2
LINTTAGS	+= -erroff=E_ASM_IMPOSSIBLE_CONSTRAINT
LINTTAGS	+= -erroff=E_ASM_UNUSED_PARAM
LINTTAGS	+= -erroff=E_NOP_IF_STMT
LINTTAGS	+= -erroff=E_ZERO_OR_NEGATIVE_SUBSCRIPT

CERRWARN	+= -_gcc=-Wno-empty-body

# These sources only compile with gcc.  Workaround a confluence of cruft
# regarding dmake and shadow compilation by neutering the sun compiler.
#amd64_CC	= $(ONBLD_TOOLS)/bin/$(MACH)/cw -_gcc
#CFLAGS		+= -_cc=-xdryrun

ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)
PRE_INC_PATH	= -I$(COMPAT)/freebsd -I$(COMPAT)/freebsd/amd64 \
	-I$(CONTRIB)/freebsd -I$(CONTRIB)/freebsd/amd64
INC_PATH	+= -I$(UTSBASE)/i86pc/io/vmm -I$(UTSBASE)/i86pc/io/vmm/io
AS_INC_PATH	+= -I$(UTSBASE)/i86pc/io/vmm -I$(OBJS_DIR)

CFLAGS		+= -_gcc=-Wimplicit-function-declaration
# The FreeBSD %# notation makes gcc gripe
CFLAGS		+= -_gcc=-Wno-format

$(OBJS_DIR)/vmm.o := CERRWARN += -_gcc=-Wno-pointer-sign -_gcc=-Wno-type-limits
$(OBJS_DIR)/svm.o := CERRWARN += -_gcc=-Wno-pointer-sign -_gcc=-Wno-type-limits

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

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

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
