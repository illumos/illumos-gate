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
# Copyright (c) 2018, Joyent, Inc.
#

PROG =		iasl

include ../Makefile.tools

IASL_SRC_DIR =	$(SRC)/cmd/acpi/iasl
IASL_OBJ_DIR =	$(SRC)/tools/iasl

include $(IASL_SRC_DIR)/Makefile.iasl

$(OBJS) :=	VPATH += $(IASL_SRC_DIR)
GM4FLAGS +=	-I$(IASL_SRC_DIR)
CPPFLAGS +=	-I$(IASL_SRC_DIR)

# Without this, $SRC/tools/iasl will fail to build if $SRC/cmd/acpi/iasl is not
# built first.
aslcompilerlex.c aslcompilerparse.c aslcompiler.y.h: $(IASL_OBJ_DIR)/aslcompiler.y

install: all .WAIT $(ROOTONBLDMACHPROG)

include ../Makefile.targ
