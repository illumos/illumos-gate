#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/i386/Makefile

.KEEP_STATE:

include $(SRC)/lib/Makefile.lib

include ../Makefile.targ

# Add arch specific objects here
OBJECTS +=

# Uncomment the following if the linker complains
i386_C_PICFLAGS  = $(C_BIGPICFLAGS)

# These include paths must be searched before includes paths in CPPFLAGS
CFLAGS +=	-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5 \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/asn.1 \
		-I$(SRC)/lib/gss_mechs/mech_krb5/profile \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/ccache/file \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/ccache/stdio \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/keytab/file \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/os \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/rcache \
		-I$(SRC)/lib/gss_mechs/mech_krb5/et \
		-I$(SRC)/uts/common/gssapi/ \
		-I$(SRC)/uts/common/gssapi/include \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include

include $(SRC)/lib/gss_mechs/mech_krb5/spec/Makefile.spec

install:
