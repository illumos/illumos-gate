#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

SUBDIRS	=	$(MACH)

SQLITE_VERSION = 2.8.15-repcached

VERS = .1

include $(SRC)/lib/Makefile.lib

ENCODING  = ISO8859

SRCDIR=	src

HDRS=           sqlite.h sqlite-misc.h
ROOTHDRDIR=     $(ROOT)/usr/include/sqlite-sys
ROOTHDRS=       $(HDRS:%=$(ROOTHDRDIR)/%)
CHECKHDRS=      $(HDRS:%.h=%.check)
CLOBBERFILES +=	sqlite.h

.KEEP_STATE:

all	:= TARGET= all
clean	:= TARGET= clean
clobber	:= TARGET= clobber
install	:= TARGET= install


# This is the default Makefile target.  The objects listed here
# are what get build when you type just "make" with no arguments.
#
all install:	sqlite.h $(SUBDIRS)
clobber:	$(SUBDIRS)

$(ROOTHDRDIR):
	$(INS.dir)

$(ROOTHDRDIR)/%: % $(ROOTHDRDIR)
	$(INS.file)

install_h:	sqlite.h $(ROOTHDRS)

check:

#
# we don't want this output different every time, so we just suppress it
#
sqlite.h: $(SRCDIR)/sqlite.h.in
	@echo "Generating $@"; \
	 sed -e 's"--VERS--"$(SQLITE_VERSION)"' \
	    -e s/--ENCODING--/$(ENCODING)/ \
	    $(SRCDIR)/sqlite.h.in > $@

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/lib/Makefile.targ
