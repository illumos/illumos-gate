#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/kadm5/clnt/spec/sparc/Makefile

.KEEP_STATE:

include	../Makefile.targ

# Add arch specific objects here
OBJECTS	+=

include	$(SRC)/lib/Makefile.lib
include $(SRC)/lib/Makefile.spec

# Uncomment the following if the linker complains
#sparc_C_PICFLAGS  = -K PIC

# These include paths must be searched before includes paths in CPPFLAGS
CFLAGS += -I$(SRC)/lib/krb5/kadm5 -I$(SRC)/lib/krb5/kadm5/clnt \
		-I$(SRC)/lib/krb5 -I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5 \
		-I$(SRC)/uts/common/gssapi/include/ \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include 
CPPFLAGS +=	-Dgssrpc=rpc

install: $(KRB5ABILIB)
