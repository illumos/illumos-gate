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
# Copyright 2022 Toomas Soome <tsoome@me.com>
#
include $(SRC)/Makefile.master

ROOT_BOOT=		$(ROOT)/boot
ROOT_BOOT_DEFAULTS=	$(ROOT)/boot/defaults
ROOT_BOOT_FORTH=	$(ROOT)/boot/forth
ROOT_BOOT_CONF=		$(ROOT)/boot/conf.d
ROOTBOOTFILES=$(FILES:%=$(ROOT_BOOT)/%)
ROOTBOOTFORTH=$(FORTH:%=$(ROOT_BOOT_FORTH)/%)
ROOTBOOTDEFAULTS=$(DEFFILES:%=$(ROOT_BOOT_DEFAULTS)/%)
FILEMODE=0444

FORTH =	beastie.4th
FORTH +=	beadm.4th
FORTH +=	brand.4th
FORTH +=	brand-illumos.4th
FORTH +=	check-password.4th
FORTH +=	color.4th
FORTH +=	delay.4th
FORTH +=	efi.4th
FORTH +=	frames.4th
FORTH +=	loader.4th
DEFFILES =	loader.conf
FORTH +=	logo-beastie.4th
FORTH +=	logo-beastiebw.4th
FORTH +=	logo-fbsdbw.4th
FORTH +=	logo-illumos.4th
FORTH +=	logo-orb.4th
FORTH +=	logo-orbbw.4th
FORTH +=	menu.4th
FORTH +=	menu.rc
FORTH +=	menu-commands.4th
FORTH +=	menusets.4th
FORTH +=	pcibios.4th
FORTH +=	screen.4th
FORTH +=	shortcuts.4th
FORTH +=	support.4th
FORTH +=	version.4th
FILES +=	illumos-logo.png
FILES +=	illumos-brand.png
FILES +=	loader.rc

all clean clobber:

install: $(ROOT_BOOT_DEFAULTS) $(ROOT_BOOT_FORTH) $(ROOTBOOTFILES) \
	$(ROOTBOOTDEFAULTS) $(ROOT_BOOT_CONF) $(ROOTBOOTFORTH)

$(ROOT_BOOT)/%: % $(ROOT_BOOT)
	$(INS.file)

$(ROOT_BOOT_DEFAULTS)/%: % $(ROOT_BOOT_DEFAULTS)
	$(INS.file)

$(ROOT_BOOT_FORTH)/%: % $(ROOT_BOOT_FORTH)
	$(INS.file)

$(ROOT_BOOT_DEFAULTS) $(ROOT_BOOT_CONF) $(ROOT_BOOT_FORTH):
	$(INS.dir)
