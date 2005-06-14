#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the fas driver kernel module.
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
SCCS		= sccs
TEST		= test

include $(UTSBASE)/sparc/Makefile.sparc

#
#	lock_lint rules
#
all:	warlock warlock.1394 warlock.audio warlock.ecpp warlock.scsi \
	warlock.smartcard warlock.usb warlock.ib

warlock: $(MODULE).ok 

warlock.ok: ddi_dki_impl.ll scsi.ll
	$(TOUCH) $@

%.ll: $(UTSBASE)/common/io/warlock/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

warlock.usb:
	@cd ../usba; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ohci; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../uhci; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ehci; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../hid; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../scsa2usb; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usb_ac; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usb_as; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usb_ah; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ugen; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usb_mid; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usbprn; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usbser; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usbser_edge; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usbskel; rm -f *.ll *.ok; $(MAKE) warlock

warlock.scsi:
	@cd ../dad; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../dada; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../esp; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../fas; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../glm; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ifp; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../isp; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../sd; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ses; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../st; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ssd; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../uata; rm -f *.ll *.ok; $(MAKE) warlock

warlock.1394:
	@cd ../s1394; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../hci1394; rm -f *.ll *.ok; $(MAKE) warlock

warlock.ecpp:
	@cd ../ecpp; rm -f *.ll *.ok; $(MAKE) warlock

warlock.audio:
	@cd ../audiosup; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../mixer; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../amsrc1; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../amsrc2; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../audio810; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../audiovia823x; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../audiocs; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../audioens; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../audiots; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usb_ac; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usb_as; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usb_ah; rm -f *.ll *.ok; $(MAKE) warlock

warlock.smartcard:
	@cd ../../sun4u/scmi2c; rm -f *.ll *.ok; make warlock

warlock.ib:
	@cd ../ibmf; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../tavor; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ib; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ibtl; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ibcm; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ibd; rm -f *.ll *.ok; $(MAKE) warlock
