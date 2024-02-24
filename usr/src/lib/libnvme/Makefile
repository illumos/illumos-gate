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
# Copyright 2024 Oxide Computer Company
#

include ../Makefile.lib

HDRS = libnvme.h
HDRDIR = common

#
# Most of the types that we use to talk to the kernel have embedded pointers or
# sizes in them. For the ones that should be agnostic, verify that here.
#
TYPECHECK_LIB =	libnvme.so.1
TYPELIST = \
	nvme_ioctl_ctrl_info_t	\
	nvme_ioctl_common_t	\
	nvme_ioctl_format_t	\
	nvme_ioctl_fw_commit_t	\
	nvme_ioctl_lock_t	\
	nvme_ioctl_unlock_t

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
