#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libsasl/Makefile
#

include	../Makefile.lib

HDRS=		sasl.h		saslplug.h	saslutil.h	prop.h
HDRDIR=		include
ROOTHDRDIR=	$(ROOT)/usr/include/sasl

SUBDIRS =	$(MACH)

$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

LIBRARY=        libsasl.a
POFILE=         $(LIBRARY:.a=.po)
MSGFILES=	lib/canonusr.c lib/checkpw.c lib/client.c lib/common.c \
			lib/external.c lib/server.c lib/seterror.c \
			plugin/plugin_common.c \
			$(SRC)/lib/sasl_plugins/cram/cram.c \
			$(SRC)/lib/sasl_plugins/digestmd5/digestmd5.c \
			$(SRC)/lib/sasl_plugins/gssapi/gssapi.c \
			$(SRC)/lib/sasl_plugins/plain/plain.c

.KEEP_STATE:

all clean clobber install: spec .WAIT $(SUBDIRS)

lint: $(SUBDIRS)

install_h:	$(ROOTHDRS)

check:	$(CHECKHDRS)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

include $(SRC)/Makefile.msg.targ

$(SUBDIRS) spec: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

# EXPORT DELETE START
# CRYPT DELETE START
# Special target to clean up the source tree for export distribution
# Warning: This target changes the source tree
EXPORT_SRC:
	$(RM) Makefile+ \
		lib/client.c+ \
		lib/server.c+ \
		lib/common.c+ \
		lib/saslint.h+ \
		include/plugin_common.h+

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< lib/client.c > lib/client.c+
	$(MV) lib/client.c+ lib/client.c

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< lib/server.c > lib/server.c+
	$(MV) lib/server.c+ lib/server.c

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< lib/common.c > lib/common.c+
	$(MV) lib/common.c+ lib/common.c

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< lib/saslint.h > lib/saslint.h+
	$(MV) lib/saslint.h+ lib/saslint.h

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< include/plugin_common.h > include/plugin_common.h+
	$(MV) include/plugin_common.h+ include/plugin_common.h

	$(SED) -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile

	$(CHMOD) 444 Makefile \
		lib/client.c \
		lib/server.c \
		lib/common.c \
		lib/saslint.h \
		include/plugin_common.h

CRYPT_SRC:
	$(RM) Makefile+ lib/common.c+

	$(SED) -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		< lib/common.c | $(SED) -e "/EXPORT DELETE/d" \
		> lib/common.c+
	$(MV) lib/common.c+ lib/common.c

	$(SED) -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		< lib/client.c | $(SED) -e "/EXPORT DELETE/d" \
		> lib/client.c+
	$(MV) lib/client.c+ lib/client.c

	$(SED) -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		< lib/server.c | $(SED) -e "/EXPORT DELETE/d" \
		> lib/server.c+
	$(MV) lib/server.c+ lib/server.c

	$(SED) -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		< lib/saslint.h | $(SED) -e "/EXPORT DELETE/d" \
		> lib/saslint.h+
	$(MV) lib/saslint.h+ lib/saslint.h

	$(SED) -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		< include/plugin_common.h | $(SED) -e "/EXPORT DELETE/d" \
		> include/plugin_common.h+
	$(MV) include/plugin_common.h+ include/plugin_common.h

	$(SED) -e "/^# CRYPT DELETE START/,/^# CRYPT DELETE END/d" \
		< Makefile | $(SED) -e "/^# EXPORT DELETE/d" > Makefile+
	$(MV) Makefile+ Makefile

	$(CHMOD) 444 Makefile \
		lib/client.c \
		lib/server.c \
		lib/common.c \
		lib/saslint.h \
		include/plugin_common.h

# CRYPT DELETE END
# EXPORT DELETE END

include ../Makefile.targ

.PARALLEL: $(SUBDIRS)
