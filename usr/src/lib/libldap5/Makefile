#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libldap5/Makefile
#

include			../Makefile.lib

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint
_msg :=		TARGET= _msg

LIBRARY=        libldap.a
TEXT_DOMAIN =   SUNW_OST_OSLIB
XGETFLAGS=
POFILE=         $(LIBRARY:.a=.po)
POFILES=        generic.po

.KEEP_STATE:

all clean clobber install: spec .WAIT $(SUBDIRS)

lint:
	@ $(ECHO) "usr/src/lib/libldap5 is third-party code that"
	@ $(ECHO) "will never be made lint-clean: skipping"

# install rule for install_h target
$(ROOTHDRDIR)/%: %
	$(INS.file)

install_h: $(ROOTHDRS)

check: $(CHECKHDRS)

_msg:   $(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(RM) generic.po
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(MSGDOMAIN):
	$(INS.dir)

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS)  sources/ldap/*/*.[ch]*
	sed "/^domain/d" < messages.po  > $@
	$(RM) messages.po

$(SUBDIRS) spec: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
