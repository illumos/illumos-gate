#
# Copyright (c) 1997-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI" 
#
# lib/krb5/db2/Makefile

include		../Makefile.lib

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

SUBDIRS=	spec $(MACH)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint
_msg :=		TARGET= _msg

README=		README.db2
ROOTREADME=	$(README:%=$(ROOTLIBDIR)/%)
$(ROOTLIBDIR)/$(README) :=	FILEMODE= 444

.KEEP_STATE:

all clean clobber lint _msg: $(SUBDIRS)

$(ROOTLIBDIR):
	$(INS.dir)

$(ROOTLIBDIR)/%: %
	$(INS.file)

install:   $(ROOTLIBDIR) $(ROOTREADME) $(SUBDIRS)

$(MACH) spec: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
