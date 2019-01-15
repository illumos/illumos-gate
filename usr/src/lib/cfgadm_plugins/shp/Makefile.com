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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY= shp.a
VERS= .1
OBJECTS= shp.o pci_strings.o

# include library definitions
include ../../../Makefile.lib

SRCDIR =	../common

USR_LIB_DIR		= $(ROOT)/usr/lib
USR_LIB_DIR_CFGADM	= $(USR_LIB_DIR)/cfgadm
USR_LIB_DIR_CFGADM_64	= $(USR_LIB_DIR_CFGADM)/$(MACH64)

ROOTLIBDIR= $(USR_LIB_DIR_CFGADM)
ROOTLIBDIR64= $(USR_LIB_DIR_CFGADM_64)

SRCS=		../common/shp.c $(SRC)/common/pci/pci_strings.c

LIBS = $(DYNLIB)

CPPFLAGS +=     -I$(SRC)/lib/libhotplug/common
CPPFLAGS +=	-D_POSIX_PTHREAD_SEMANTICS
CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-lc -ldevinfo -lhotplug

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-char-subscripts
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-unused-variable

# not linted
SMATCH=off

.KEEP_STATE:

all: $(LIBS)

lint:   lintcheck

# Create target directories
$(USR_LIB_DIR):
	-$(INS.dir.root.sys)

$(USR_LIB_DIR_CFGADM): $(USR_LIB_DIR)
	-$(INS.dir.bin.bin)

$(USR_LIB_DIR_CFGADM_64): $(USR_LIB_DIR_CFGADM)
	-$(INS.dir.bin.bin)

$(USR_LIB_DIR_CFGADM)/%: % $(USR_LIB_DIR_CFGADM)
	-$(INS.file)

$(USR_LIB_DIR_CFGADM_64)/%: % $(USR_LIB_DIR_CFGADM_64)
	-$(INS.file)

# include library targets
include ../../../Makefile.targ

pics/shp.o: ../common/shp.c
	$(COMPILE.c) -o $@ ../common/shp.c
	$(POST_PROCESS_O)

pics/pci_strings.o: $(SRC)/common/pci/pci_strings.c
	$(COMPILE.c) -o $@ $(SRC)/common/pci/pci_strings.c
	$(POST_PROCESS_O)
