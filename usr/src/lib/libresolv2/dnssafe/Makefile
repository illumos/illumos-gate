#
# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libresolv2/dnssafe/Makefile

include		../../../Makefile.master
include		../../Makefile.lib

SUBDIRS=	spec $(MACH) $(BUILD64) $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
delete :=	TARGET= delete
install :=	TARGET= install
lint :=		TARGET= lint
_msg :=		TARGET= _msg
package :=	TARGET= package

LIBRARY= 	dnssafe.a
TEXT_DOMAIN=	SUNW_OST_OSLIB
XGETFLAGS=	-a
POFILE=		$(LIBRARY:.a=.po)
POFILES=	generic.po

SED=	sed
GREP=	grep
CP=	cp

.KEEP_STATE:

all clean clobber delete install lint package: $(SUBDIRS)

# install rule for install_h target
$(ROOTHDRDIR)/%: %
	$(INS.file)

install_h: $(ROOTHDRS)

check: $(CHECKHDRS)

$(MACH) $(MACH64) spec: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):	$(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) *.[ch]* */*.[ch]*
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

FRC:
