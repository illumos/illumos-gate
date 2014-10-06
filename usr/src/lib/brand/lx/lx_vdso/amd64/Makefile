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
# Copyright 2014 Joyent, Inc.  All rights reserved.
#

ISASRCDIR=.

include ../Makefile.com
include $(SRC)/lib/Makefile.lib.64

#
# You might ask, why aren't we overriding BUILD.SO in Makefile.com.
# That's a sad story. The answer is that Makefile.lib.64 includes
# Makefile.master.64 which redefines BUILD.SO, leaving us in an
# unfortunate jumble. Therefore we have to redefine it in the
# lower-level Makefile.
#
BUILD.SO =	$(LD) -o $@ $(GSHARED) $(DYNFLAGS) $(PICS) $(LDLIBS)

ASSYMDEP_OBJS = lx_vdso.o

CLOBBERFILES	= $(ROOTLIBDIR64)/$(DYNLIB) $(ROOTLIBDIR64)/$(LINTLIB)

install: all $(ROOTLIBS64)
