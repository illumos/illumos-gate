#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../Makefile.lib

HDRS =		tcpd.h
CHECKHDRS =
HDRDIR =	.
SUBDIRS	=	$(MACH)

all := 		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
install	:=	TARGET = install
lint :=		TARGET = lint

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

all install: THIRDPARTYLICENSE

install_h:	$(ROOTHDRS)

check:		$(CHECKHDRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

THIRDPARTYLICENSE: DISCLAIMER
	$(GREP) -v '\*\*\*\*' DISCLAIMER > $@

CLOBBERFILES += THIRDPARTYLICENSE

include ../Makefile.targ
