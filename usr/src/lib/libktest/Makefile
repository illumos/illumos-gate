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
# Copyright 2025 Oxide Computer Company
#

include ../Makefile.lib

HDRS = libktest.h
HDRDIR = common

# The 32-bit library is omitted for now.  This can be changed when the ktest
# device gains 32-bit compatibility in its ioctl handlers.
$(BUILD64)SUBDIRS += $(MACH64)
CHECKHDRS =

all := TARGET = all
clean := TARGET = clean
clobber := TARGET = clobber
install := TARGET = install

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

install: install_h $(SUBDIRS)

install_h: $(ROOTHDRS)

check: $(CHECKHDRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
