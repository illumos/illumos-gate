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
# Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
#
#	sparc architecture dependent
#
# uts/sparc/warlock/Makefile
#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= warlock
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)

.KEEP_STATE:

CFLAGS += -I../../common/sys -I../../sun/sys/scsi -D_KERNEL
#
#	Defines for local commands.
#
WARLOCK		= warlock
WLCC		= wlcc
TOUCH		= touch
TEST		= test

include $(UTSBASE)/sparc/Makefile.sparc

#
#	lock_lint rules
#
all:	warlock warlock.1394 warlock.ecpp warlock.scsi \
	warlock.usb warlock.ib warlock.sata warlock.wc

warlock: $(MODULE).ok 

warlock.ok: ddi_dki_impl.ll scsi.ll
	$(TOUCH) $@

%.ll: $(UTSBASE)/common/io/warlock/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

warlock.usb:
	@cd ../usba; $(MAKE) clean; $(MAKE) warlock
	@cd ../ohci; $(MAKE) clean; $(MAKE) warlock
	@cd ../uhci; $(MAKE) clean; $(MAKE) warlock
	@cd ../ehci; $(MAKE) clean; $(MAKE) warlock
	@cd ../hid; $(MAKE) clean; $(MAKE) warlock
	@cd ../scsa2usb; $(MAKE) clean; $(MAKE) warlock
	@cd ../usb_ac; $(MAKE) clean; $(MAKE) warlock
	@cd ../usb_as; $(MAKE) clean; $(MAKE) warlock
	@cd ../usb_ah; $(MAKE) clean; $(MAKE) warlock
	@cd ../ugen; $(MAKE) clean; $(MAKE) warlock
	@cd ../usb_mid; $(MAKE) clean; $(MAKE) warlock
	@cd ../usb_ia; $(MAKE) clean; $(MAKE) warlock
	@cd ../usbprn; $(MAKE) clean; $(MAKE) warlock
	@cd ../usbser; $(MAKE) clean; $(MAKE) warlock
	@cd ../usbsksp; $(MAKE) clean; $(MAKE) warlock
	@cd ../usbsprl; $(MAKE) clean; $(MAKE) warlock
	@cd ../usbsacm; $(MAKE) clean; $(MAKE) warlock
	@cd ../usbecm; $(MAKE) clean; $(MAKE) warlock
	@cd ../usbskel; $(MAKE) clean; $(MAKE) warlock

warlock.scsi:
	@cd ../dad; $(MAKE) clean; $(MAKE) warlock
	@cd ../dada; $(MAKE) clean; $(MAKE) warlock
	@cd ../esp; $(MAKE) clean; $(MAKE) warlock
	@cd ../fas; $(MAKE) clean; $(MAKE) warlock
	@cd ../sd; $(MAKE) clean; $(MAKE) warlock
	@cd ../ses; $(MAKE) clean; $(MAKE) warlock
	@cd ../st; $(MAKE) clean; $(MAKE) warlock
	@cd ../ssd; $(MAKE) clean; $(MAKE) warlock

warlock.1394:
	@cd ../s1394; $(MAKE) clean; $(MAKE) warlock
	@cd ../hci1394; $(MAKE) clean; $(MAKE) warlock
	@cd ../scsa1394; $(MAKE) clean; $(MAKE) warlock
	@cd ../av1394; $(MAKE) clean; $(MAKE) warlock

warlock.ecpp:
	@cd ../ecpp; $(MAKE) clean; $(MAKE) warlock

warlock.ib:
	@cd ../ibmf; $(MAKE) clean; $(MAKE) warlock
	@cd ../ib; $(MAKE) clean; $(MAKE) warlock
	@cd ../ibtl; $(MAKE) clean; $(MAKE) warlock
	@cd ../ibcm; $(MAKE) clean; $(MAKE) warlock
	@cd ../ibd; $(MAKE) clean; $(MAKE) warlock

warlock.sata:
	@cd ../sata; $(MAKE) clean; $(MAKE) warlock
	@cd ../si3124; $(MAKE) clean; $(MAKE) warlock
	@cd ../ahci; $(MAKE) clean; $(MAKE) warlock
	@cd ../nv_sata; $(MAKE) clean; $(MAKE) warlock

warlock.wc:
	@cd ../wc; $(MAKE) clean; $(MAKE) warlock
