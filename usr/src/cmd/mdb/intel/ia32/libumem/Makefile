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

MODULE = libumem.so
MDBTGT = proc

MODSRCS_DIR = ../../../common/modules/genunix

MODSRCS = \
	dist.c \
	kgrep.c \
	leaky.c \
	leaky_subr.c \
	libumem.c \
	misc.c \
	proc_kludges.c \
	umem.c

include ../../../../Makefile.cmd

CPPFLAGS += -I$(SRC)/lib/libc/inc
CPPFLAGS += -I$(SRC)/lib/libumem/common
CPPFLAGS += -I$(MODSRCS_DIR)

include ../../Makefile.ia32
include ../../../Makefile.module

dmod/$(MODULE) := LDLIBS += -lproc -lm

CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized

%.o: $(MODSRCS_DIR)/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

%.ln: $(MODSRCS_DIR)/%.c
	$(LINT.c) -c $<
