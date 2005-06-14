#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

GRUB	= grub-0.95

SUBDIRS	= $(GRUB)

SPLASH_IMAGE = splash.xpm.gz
GRUB_MENU = menu.lst
INSTALL_MENU = install_menu

INST_TARGETS = $(ROOT_BOOT_GRUB)/$(SPLASH_IMAGE)
INST_TARGETS += $(ROOT_BOOT_GRUB)/$(GRUB_MENU)
INST_TARGETS += $(ROOT_BOOT_GRUB)/$(INSTALL_MENU)

all: $(SUBDIRS)

install: $(SUBDIRS) $(INST_TARGETS)


# Makefiles in the GRUB source tree are named "Makefile.solaris".
$(GRUB): FRC
	cd $@; pwd; $(MAKE) -f Makefile.solaris $(TARGET)

$(ROOT_BOOT_GRUB)/%: $(ROOT_BOOT_GRUB) %
	$(INS.file)

$(ROOT_BOOT_GRUB):
	$(INS.dir)


clean: $(SUBDIRS)

clobber: $(SUBDIRS)
	$(RM) $(INST_TARGETS)

FRC:
