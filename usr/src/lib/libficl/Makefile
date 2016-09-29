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
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

include		../Makefile.lib

HDRS=		ficllocal.h

HDRDIR=		$(SRC)/common/ficl

SUBDIRS=	softcore $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install

.KEEP_STATE:

all install: install_h $(SUBDIRS)

clean clobber: $(SUBDIRS)

install_h:	$(PLATHDRDIR) $(ROOTHDRS)

check:		$(CHECKHDRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(ROOTHDRDIR)/%: ./%
	$(INS.file)

FRC:

include $(SRC)/lib/Makefile.targ
