# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source. A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.

# Copyright 2023 OmniOS Community Edition (OmniOSce) Association.

MODULE = vmm.so
MDBTGT = kvm

MODSRCS = vmm.c

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/mdb/intel/Makefile.amd64
include $(SRC)/cmd/mdb/Makefile.module

CPPFLAGS += -DMP -D_MACHDEP
CPPFLAGS += -I../../../../common
CPPFLAGS += -I$(SRC)/uts/intel/io/vmm
CPPFLAGS += -I$(SRC)/uts/intel/
CPPFLAGS += -I$(SRC)/uts/i86pc

