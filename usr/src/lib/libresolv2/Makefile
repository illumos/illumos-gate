#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libresolv2/Makefile
#

include		../../Makefile.master
include		../Makefile.lib

MANIFEST=	client.xml
MANIFESTDIR=	$(ROOT)/var/svc/manifest/network/dns
ROOTMANIFEST=	$(MANIFEST:%=$(MANIFESTDIR)/%)

$(ROOTMANIFEST) :=	FILEMODE = 444
$(ROOTMANIFEST) :=	OWNER = root
$(ROOTMANIFEST) :=	GROUP = bin

CHKMANIFEST=	$(MANIFEST:%.xml=%.xmlchk)

SUBDIRS=	include spec $(MACH)
$(BUILD64)SUBDIRS +=	$(MACH64)
SUBDIRS +=	.WAIT irs

# EXPORT DELETE START
# CRYPT DELETE START
SUBDIRS +=	cylink dnssafe
# CRYPT DELETE END
# EXPORT DELETE END

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint
_msg :=		TARGET= _msg

LIBRARY= 	libresolv.a
TEXT_DOMAIN=	SUNW_OST_OSLIB
XGETFLAGS=	-a
POFILE=		$(LIBRARY:.a=.po)
POFILES=	generic.po

SED=	sed
GREP=	grep
CP=	cp

.KEEP_STATE:

all clean clobber lint: $(SUBDIRS)

install: $(SUBDIRS) $(ROOTMANIFEST)

$(ROOTMANIFEST): $(MANIFESTDIR)

$(MANIFESTDIR):
	$(INS.dir)

$(MANIFESTDIR)/%: %
	$(INS.file)                                                             

# install rule for install_h target
$(ROOTHDRDIR)/%: %
	$(INS.file)

install_h: $(ROOTHDRS)

check: $(CHECKHDRS) $(CHKMANIFEST)

# EXPORT DELETE START
# CRYPT DELETE START
# Special targets to clean up the source tree for export distribution
# Warning: These target change the source tree
EXPORT_SRC:
	$(RM) Makefile+
	$(SED) -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile
	/usr/bin/find cylink dnssafe common/cylink common/dnssafe \
		-name SCCS -prune -o -type f -exec $(RM) {} \;

CRYPT_SRC:
	$(RM) Makefile+
	$(SED) -e "/^# CRYPT DELETE START/,/^# CRYPT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile
	/usr/bin/find cylink dnssafe common/cylink common/dnssafe \
		-name SCCS -prune -o -type f -exec $(RM) {} \;

# CRYPT DELETE END
# EXPORT DELETE END

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

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET); echo

FRC:
