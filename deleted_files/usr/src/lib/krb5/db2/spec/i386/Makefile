#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/db2/spec/i386/Makefile

.KEEP_STATE:

include	../Makefile.targ

# Add arch specific objects here
OBJECTS	+=

include	$(SRC)/lib/Makefile.lib
include $(SRC)/lib/Makefile.spec

# Uncomment the following if the linker complains
#i386_C_PICFLAGS  = -K PIC

# These include paths must be searched before includes paths in CPPFLAGS
CFLAGS += -I$(SRC)/lib/krb5/db2/mpool \
		-I$(SRC)/lib/krb5/db2/db \
		-I$(SRC)/lib/krb5/db2/hash \
		-I$(SRC)/lib/krb5/db2/btree \
		-I$(SRC)/lib/krb5/db2/recno \
		-I$(SRC)/lib/krb5/db2/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/

install: $(KRB5ABILIB) 
