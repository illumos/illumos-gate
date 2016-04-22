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
# Copyright 2016 Joyent, Inc.
#

ISASRCDIR=.
TARGET_ARCH=$(MACH)

include ../Makefile.com

ASFLAGS += -D__$(MACH)

SONAME = linux-gate.so.1

#
# You might ask, why aren't we overriding BUILD.SO in Makefile.com.
# See the amd64 Makefile for more answers
#
BUILD.SO =	$(LD) -o $@ $(GSHARED) $(DYNFLAGS) $(PICS) $(LDLIBS)

ASSYMDEP_OBJS = lx_vdso.o

CLOBBERFILES	= $(ROOTLIBDIR)/$(DYNLIB) $(ROOTLIBDIR)/$(LINTLIB)

# Set the object entry point for __vsyscall-ers
entryfix: $(DYNLIB)
	$(ELFEDIT) -e "ehdr:e_entry \
	    $$($(ELFEDIT) -re 'sym:st_value -osimple __vsyscall' $(DYNLIB))" \
	    $(DYNLIB)

all: entryfix

install: all $(ROOTLIBS)
