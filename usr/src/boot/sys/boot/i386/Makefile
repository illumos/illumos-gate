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
# Copyright 2015 Toomas Soome <tsoome@me.com>
#

include $(SRC)/Makefile.master


# likely targets for removal, keeping around just in case...
# SUBDIRS=	boot0 boot0sio kgzldr libfirewire
# current targets
SUBDIRS=	pmbr btx cdboot gptzfsboot libi386 loader pxeldr
INSTDIRS=	pmbr cdboot gptzfsboot loader pxeldr

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber

.KEEP_STATE:

all clean clobber: $(SUBDIRS)

install: all .WAIT $(INSTDIRS)

pxeldr: loader

FRC:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)
