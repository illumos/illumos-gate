#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/Makefile
#
# This make file will build mech_krb5.so.1. This shared object
# contains all the functionality needed to support the Kereros V5 GSS-API
# mechanism. No other Kerberos libraries are needed.
#

include ../../../Makefile.master

SUBDIRS= spec .WAIT $(MACH) $(BUILD64) $(MACH64)

# include library definitions
include ../../Makefile.lib

GREP= find . \( -name SCCS -prune -o -name '*.[ch]' \) -print | sort | xargs grep

sparcv9_C_PICFLAGS =  -K PIC
TEXT_DOMAIN = SUNW_OST_NETRPC
POFILE = mech_krb5.po
POFILES = generic.po

HDRS=

CHECKHDRS= $(HDRS:%.h=%.check)

$(ROOTDIRS)/%:  %
	$(INS.file)

all :=          TARGET= all
clean :=        TARGET= clean
clobber :=      TARGET= clobber
install :=      TARGET= install
lint :=         TARGET= lint

.KEEP_STATE:

all:    .WAIT $(SUBDIRS)

lint:   .WAIT $(SUBDIRS)

install: install_dir all .WAIT $(SUBDIRS)

# override ROOTLIBDIR and ROOTLINKS
ROOTLIBDIR=     $(ROOT)/usr/lib/gss

install_dir:	$(ROOTLIBDIR) $(BUILD64)

install_h:

clean:  $(SUBDIRS)

clobber: $(SUBDIRS)
	$(RM) $(POFILE) $(POFILES)

check: $(CHECKHDRS)

do_pkg:
	cd pkg ; pwd ; $(MAKE) install

$(ROOTLIBDIR):
	$(INS.dir)


# include library targets
# include ../../Makefile.targ

spec $(MACH) $(MACH64):      FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

# EXPORT DELETE START
# Special target to clean up the source tree for export distribution
# Warning: This target changes the source tree
EXPORT_SRC:
	$(RM) Makefile+ Makefile.mech_krb5+\
		crypto/des/afsstring2key.c+ \
		crypto/des/string2key.c+ \
		mech/k5mech.c+

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< crypto/des/afsstring2key.c > crypto/des/afsstring2key.c+
	$(MV) crypto/des/afsstring2key.c+ crypto/des/afsstring2key.c

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< crypto/des/string2key.c > crypto/des/string2key.c+
	$(MV) crypto/des/string2key.c+ crypto/des/string2key.c

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< mech/k5mech.c > mech/k5mech.c+
	$(MV) mech/k5mech.c+ mech/k5mech.c

	$(SED) -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile.mech_krb5 > Makefile.mech_krb5+
	$(MV) Makefile.mech_krb5+ Makefile.mech_krb5

	$(SED) -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile

	$(CHMOD) 444 Makefile Makefile.mech_krb5 \
		crypto/des/afsstring2key.c \
		crypto/des/string2key.c \
		mech/k5mech.c


# CRYPT DELETE START
# Special target to clean up the source tree for domestic distribution
# Warning: This target changes the source tree
CRYPT_SRC:
	$(RM) Makefile+ mech/k5mech.c+

	$(SED) -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		> mech/k5mech.c+ < mech/k5mech.c
	$(MV) mech/k5mech.c+ mech/k5mech.c

	$(SED) -e "/^# CRYPT DELETE START/,/^# CRYPT DELETE END/d"	\
			< Makefile 				\
	   | $(SED) -e "/EXPORT DELETE/d"				\
			> Makefile+
	$(MV) Makefile+ Makefile

	$(CHMOD) 444 mech/k5mech.c Makefile

# CRYPT DELETE END
# EXPORT DELETE END



FRC:

_msg: $(MSGDOMAIN) .WAIT $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po: FRC
	$(RM) messages.po
	-$(XGETTEXT) $(XGETFLAGS) `$(GREP) -s -l gettext`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

$(MSGDOMAIN):
	$(INS.dir)
