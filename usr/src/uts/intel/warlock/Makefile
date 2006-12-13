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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# uts/intel/warlock/Makefile
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
SCCS		= sccs
TEST		= test

include $(UTSBASE)/intel/Makefile.intel

#
#	lock_lint rules
#
all:	warlock warlock.1394 warlock.audio warlock.ecpp warlock.scsi \
	warlock.usb warlock.ib warlock.sata

warlock: $(MODULE).ok 

warlock.ok: ddi_dki_impl.ll scsi.ll
	$(TOUCH) $@

%.ll: $(UTSBASE)/common/io/warlock/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

warlock.usb:
	@cd ../usba; make clean; $(MAKE) warlock
	@cd ../ohci; make clean; $(MAKE) warlock
	@cd ../uhci; make clean; $(MAKE) warlock
	@cd ../ehci; make clean; $(MAKE) warlock
	@cd ../hid; make clean; $(MAKE) warlock
	@cd ../scsa2usb; make clean; $(MAKE) warlock
	@cd ../usb_ac; make clean; $(MAKE) warlock
	@cd ../usb_as; make clean; $(MAKE) warlock
	@cd ../usb_ah; make clean; $(MAKE) warlock
	@cd ../ugen; make clean; $(MAKE) warlock
	@cd ../usb_mid; make clean; $(MAKE) warlock
	@cd ../usbprn; make clean; $(MAKE) warlock
	@cd ../usbser; make clean; $(MAKE) warlock
	@cd $(CLOSED)/uts/intel/usbser_edge; make clean; $(MAKE) warlock
	@cd ../usbsksp; make clean; $(MAKE) warlock
	@cd ../usbsprl; make clean; $(MAKE) warlock
	@cd ../usbsacm; make clean; $(MAKE) warlock
	@cd ../usbskel; make clean; $(MAKE) warlock

warlock.scsi:
	@cd $(CLOSED)/uts/intel/glm; make clean; $(MAKE) warlock
	@cd $(CLOSED)/uts/intel/mpt; make clean; $(MAKE) warlock
	@cd ../sd; make clean; $(MAKE) warlock
	@cd ../ses; make clean; $(MAKE) warlock
	@cd ../st; make clean; $(MAKE) warlock

warlock.1394:
	@cd ../s1394; make clean; $(MAKE) warlock
	@cd ../hci1394; make clean; $(MAKE) warlock
	@cd ../scsa1394; make clean; $(MAKE) warlock
	@cd ../av1394; make clean; $(MAKE) warlock

warlock.ecpp:
	@cd ../ecpp; make clean; $(MAKE) warlock

warlock.audio:
	@cd ../audiosup; make clean; $(MAKE) warlock
	@cd ../mixer; make clean; $(MAKE) warlock
	@cd $(CLOSED)/uts/intel/amsrc1; make clean; $(MAKE) warlock
	@cd ../amsrc2; make clean; $(MAKE) warlock
	@cd ../../i86pc/audio810; make clean; $(MAKE) warlock
	@cd ../../i86pc/audiohd; make clean; $(MAKE) warlock
	@cd ../../i86pc/audioixp; make clean; $(MAKE) warlock
	@cd $(CLOSED)/uts/i86pc/audiovia823x; make clean; $(MAKE) warlock
	@cd $(CLOSED)/uts/i86pc/audioens; make clean; $(MAKE) warlock
	@cd ../usb_ac; make clean; $(MAKE) warlock
	@cd ../usb_as; make clean; $(MAKE) warlock
	@cd ../usb_ah; make clean; $(MAKE) warlock

warlock.ib:
	@cd ../ibmf; make clean; $(MAKE) warlock
	@cd $(CLOSED)/uts/intel/tavor; make clean; $(MAKE) warlock
	@cd $(CLOSED)/uts/intel/daplt; make clean; $(MAKE) warlock
	@cd ../ib; make clean; $(MAKE) warlock
	@cd ../ibtl; make clean; $(MAKE) warlock
	@cd ../ibcm; make clean; $(MAKE) warlock
	@cd ../ibd; make clean; $(MAKE) warlock

warlock.sata:
	@cd ../sata; make clean; $(MAKE) warlock
	@cd ../si3124; make clean; $(MAKE) warlock
	@cd $(CLOSED)/uts/intel/marvell88sx; make clean; $(MAKE) warlock
