#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
.KEEP_STATE:

include ../Makefile.master
include Makefile.grub

all	:= TARGET = all
install	:= TARGET = install
clean	:= TARGET = clean
clobber	:= TARGET = clobber

GRUB	= grub-0.97

SUBDIRS	= $(GRUB)

SPLASH_IMAGE = splash.xpm.gz
GRUB_MENU = menu.lst
GRUB_DEFAULT = default
INSTALL_MENU = install_menu
CAPABILITY = capability

INST_TARGETS = $(ROOT_BOOT_GRUB)/$(SPLASH_IMAGE)
INST_TARGETS += $(ROOT_BOOT_GRUB)/$(GRUB_MENU)
INST_TARGETS += $(ROOT_BOOT_GRUB)/$(INSTALL_MENU)
INST_TARGETS += $(ROOT_BOOT_GRUB)/$(GRUB_DEFAULT)
INST_TARGETS += $(ROOT_BOOT_GRUB)/$(CAPABILITY)
INST_TARGETS += $(ROOT)/etc/default/be

$(ROOT_BOOT_GRUB)/$(GRUB_DEFAULT)   := FILEMODE = 444
$(ROOT_BOOT_GRUB)/$(CAPABILITY)   := FILEMODE = 444
$(ROOT)/etc/default/be := FILEMODE = 444

all: $(SUBDIRS)

install: $(SUBDIRS) $(INST_TARGETS)


# Makefiles in the GRUB source tree are named "Makefile.solaris".
$(GRUB): FRC
	cd $@; pwd; $(MAKE) -f Makefile.solaris $(TARGET)

$(ROOT_BOOT_GRUB)/%: $(ROOT_BOOT_GRUB) %
	$(INS.file)

$(ROOT)/etc/default/%: $(ROOT)/etc/default %
	$(INS.file)

$(ROOT_BOOT_GRUB):
	$(INS.dir)

$(ROOT)/etc/default:
	$(INS.dir)

clean clobber: $(SUBDIRS)

FRC:
