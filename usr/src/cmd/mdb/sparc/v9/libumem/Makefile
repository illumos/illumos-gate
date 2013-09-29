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

COMMONSRCS = \
	dist.c \
	libumem.c \
	misc.c \
	umem.c

KMODSRCS = \
	$(COMMONSRCS)

MODSRCS = \
	$(COMMONSRCS) \
	kgrep.c \
	leaky.c \
	leaky_subr.c \
	proc_kludges.c

#
# This signals that $(KMODSRCS) != $(MODSRCS).  There are certain features of
# the libumem dmod, such as leak detection, that we cannot yet use in the kmod.
# In most cases, the inability to use a given function is due to that function's
# dependance on libproc interfaces - interfaces which are not present in kmdb.
KMOD_SOURCES_DIFFERENT=$(POUND_SIGN)

include ../../../../Makefile.cmd

CPPFLAGS += -I$(SRC)/lib/libumem/common
CPPFLAGS += -I$(SRC)/lib/libc/inc
CPPFLAGS += -I$(MODSRCS_DIR)

include ../../../../Makefile.cmd.64
include ../../Makefile.sparcv9
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

#
# This module is somewhat unusual in that it is a proc-style dmod.  proc dmods
# are not normally built both for mdb and kmdb.  These overrides build it as a
# proc dmod and as a kvm kmod.
TARGETS = $(TARGETS_proc) $(TARGETS_kvm_kmdb)
ROOTTGTS = $(ROOTTGTS_proc)
