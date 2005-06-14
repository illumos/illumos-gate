#
# Copyright (c) 1997-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI" 
#
# lib/krb5/kadm5/clnt/Makefile

include		../../Makefile.lib

SUBDIRS=	spec $(MACH) $(BUILD64) $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

LIBRARY= 	libkadm5clnt.a
POFILE=		$(LIBRARY:%.a=%.po)
POFILES=	generic.po

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

_msg: $(MSGDOMAIN) .WAIT $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext ../*.[ch] *.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

$(MACH) $(MACH64) spec: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

$(MSGDOMAIN):
	$(INS.dir)
