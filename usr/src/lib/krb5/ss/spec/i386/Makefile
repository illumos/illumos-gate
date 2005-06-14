#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/ss/spec/i386/Makefile

include	../Makefile.targ

# Add arch specific objects here
OBJECTS	+=

include	$(SRC)/lib/Makefile.lib
include $(SRC)/lib/Makefile.spec

# Uncomment the following if the linker complains
#i386_C_PICFLAGS  = -K PIC

# These include paths must be searched before includes paths in CPPFLAGS
CFLAGS += 	-I$(SRC)/lib/krb5 -I$(SRC)/lib/krb5/ss

install: $(KRB5ABILIB)
