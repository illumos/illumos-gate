#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/ss/spec/sparcv9/Makefile

include	../Makefile.targ

# Add arch specific objects here
OBJECTS	+=

include	$(SRC)/lib/Makefile.lib
include	$(SRC)/lib/Makefile.lib.64
include $(SRC)/lib/Makefile.spec

# Uncomment the following if the linker complains
#sparcv9_C_PICFLAGS  = -K PIC

# These include paths must be searched before includes paths in CPPFLAGS
CFLAGS64 += -I$(SRC)/lib/krb5 -I$(SRC)/lib/krb5/ss

#install: $(ROOTABILIB64)
# We're not shipping libss.so 64 bit yet.
install:

