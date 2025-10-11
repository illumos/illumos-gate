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

HDRS = libi2c.h
HDRDIR = common

#
# Verify all major ioctl types that don't use embedded pointers.
#
TYPECHECK_LIB =	libi2c.so.1
TYPELIST = \
	ui2c_ctrl_nprops_t \
	ui2c_prop_info_t \
	ui2c_prop_t \
	ui2c_dev_rem_t \
	ui2c_port_addr_info_t \
	ui2c_port_info_t \
	ui2c_dev_info_t \
	ui2c_mux_info_t

SUBDIRS = $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all := TARGET = all
clean := TARGET = clean
clobber := TARGET = clobber
install := TARGET = install

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

install: install_h $(SUBDIRS)

install_h: $(ROOTHDRS)

check: $(CHECKHDRS) $(TYPECHECK)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
