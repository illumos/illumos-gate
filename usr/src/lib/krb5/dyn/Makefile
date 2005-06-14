#
# Copyright (c) 1997-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI" 
#
# lib/krb5/dyn/Makefile

include		../Makefile.lib

SUBDIRS=	spec $(MACH)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

_msg:

$(MACH) spec: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
