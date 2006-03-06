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
	warlock.smartcard warlock.usb warlock.ib warlock.sata

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
	@cd $(CLOSED)/uts/sparc/usbser_edge; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usbsksp; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usbsprl; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usbskel; rm -f *.ll *.ok; $(MAKE) warlock

warlock.scsi:
	@cd $(CLOSED)/uts/sparc/dad; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../dada; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../esp; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../fas; rm -f *.ll *.ok; $(MAKE) warlock
	@cd $(CLOSED)/uts/sparc/glm; rm -f *.ll *.ok; $(MAKE) warlock
	@cd $(CLOSED)/uts/sparc/ifp; rm -f *.ll *.ok; $(MAKE) warlock
	@cd $(CLOSED)/uts/sparc/isp; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../sd; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ses; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../st; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ssd; rm -f *.ll *.ok; $(MAKE) warlock
	@cd $(CLOSED)/uts/sparc/uata; rm -f *.ll *.ok; $(MAKE) warlock

warlock.1394:
	@cd ../s1394; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../hci1394; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../scsa1394; rm -f *.ll *.ok; $(MAKE) warlock

warlock.ecpp:
	@cd ../ecpp; rm -f *.ll *.ok; $(MAKE) warlock

warlock.audio:
	@cd ../audiosup; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../mixer; rm -f *.ll *.ok; $(MAKE) warlock
	@cd $(CLOSED)/uts/sparc/amsrc1; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../amsrc2; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../audio1575; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../audio810; rm -f *.ll *.ok; $(MAKE) warlock
	@cd $(CLOSED)/uts/sparc/audiovia823x; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../audiocs; rm -f *.ll *.ok; $(MAKE) warlock
	@cd $(CLOSED)/uts/sparc/audioens; rm -f *.ll *.ok; $(MAKE) warlock
	@cd $(CLOSED)/uts/sparc/audioixp; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../audiots; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usb_ac; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usb_as; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../usb_ah; rm -f *.ll *.ok; $(MAKE) warlock

warlock.smartcard:
	@cd $(CLOSED)/uts/sun4u/scmi2c; rm -f *.ll *.ok; $(MAKE) warlock

warlock.ib:
	@cd ../ibmf; rm -f *.ll *.ok; $(MAKE) warlock
	@cd $(CLOSED)/uts/sparc/tavor; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ib; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ibtl; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ibcm; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../ibd; rm -f *.ll *.ok; $(MAKE) warlock

warlock.sata:
	@cd ../sata; rm -f *.ll *.ok; $(MAKE) warlock
	@cd ../si3124; rm -f *.ll *.ok; $(MAKE) warlock
	@cd $(CLOSED)/uts/sparc/marvell88sx ; rm -f *.ll *.ok; $(MAKE) warlock
