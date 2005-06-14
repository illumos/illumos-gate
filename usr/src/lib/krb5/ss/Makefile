#
# Copyright (c) 1997-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/ss/Makefile

include		../Makefile.lib

SUBDIRS=	spec $(MACH)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

LIBRARY= 	libss.a

POFILE = $(LIBRARY:%.a=%.po)
POFILES = generic.po

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

$(MACH) spec: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

_msg: $(MSGDOMAIN) .WAIT $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext *.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

$(MSGDOMAIN):
	$(INS.dir)
