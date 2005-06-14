#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# Note, to build SASL msg file go to $SRC/lib/libsasl and make _msg
# target there.  Messages in sasl_plugins will be picked up from there.

include	../Makefile.lib

SUBDIRS =	cram digestmd5 gssapi plain

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

lint: $(SUBDIRS)

install_h check:

$(SUBDIRS) spec: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

# EXPORT DELETE START
# CRYPT DELETE START
# Special target to clean up the source tree for export distribution
# Warning: This target changes the source tree
EXPORT_SRC:
	$(RM) 	Makefile+ \
		digestmd5/digestmd5.c+ \
		gssapi/gssapi.c+

	$(SED) -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< digestmd5/digestmd5.c > digestmd5/digestmd5.c+
	$(MV) digestmd5/digestmd5.c+ digestmd5/digestmd5.c

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< gssapi/gssapi.c > gssapi/gssapi.c+
	$(MV) gssapi/gssapi.c+ gssapi/gssapi.c

	$(CHMOD) 444 \
		Makefile \
		digestmd5/digestmd5.c \
		gssapi/gssapi.c

CRYPT_SRC:
	$(RM) Makefile+

	$(SED) -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		< digestmd5/digestmd5.c | $(SED) -e "/EXPORT DELETE/d" \
		> digestmd5/digestmd5.c+
	$(MV) digestmd5/digestmd5.c+ digestmd5/digestmd5.c

	$(SED) -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		< gssapi/gssapi.c | $(SED) -e "/EXPORT DELETE/d" \
		> gssapi/gssapi.c+
	$(MV) gssapi/gssapi.c+ gssapi/gssapi.c

	$(SED) -e "/^# CRYPT DELETE START/,/^# CRYPT DELETE END/d" \
		< Makefile | $(SED) -e "/^# EXPORT DELETE/d" > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile digestmd5/digestmd5.c gssapi/gssapi.c

# CRYPT DELETE END
# EXPORT DELETE END

include ../Makefile.targ

.PARALLEL: $(SUBDIRS)
