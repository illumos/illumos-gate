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
#

MODULE = vmm.so
MDBTGT = kvm

MODSRCS = vmm.c

include ../../../../../Makefile.cmd
include ../../../../../Makefile.cmd.64
include ../../../Makefile.amd64
include ../../../../Makefile.module

CPPFLAGS = -D_KERNEL -D_MACHDEP
CPPFLAGS += -I$(COMPAT)/freebsd -I$(COMPAT)/freebsd/amd64
CPPFLAGS += -I$(CONTRIB)/freebsd -I$(CONTRIB)/freebsd/amd64
CPPFLAGS += -I$(SRC)/uts/common -I$(SRC)/uts/i86pc
CPPFLAGS += -I$(SRC)/cmd/mdb/common

CPPFLAGS += -_cc=-xdryrun
