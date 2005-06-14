#
# Copyright (c) 1997-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI" 
#
# lib/krb5/kdb/Makefile

include		../Makefile.lib

SUBDIRS=	spec $(MACH)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint
_msg :=		TARGET= _msg

.KEEP_STATE:

all clean clobber install lint _msg: $(SUBDIRS)

$(MACH) spec: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
