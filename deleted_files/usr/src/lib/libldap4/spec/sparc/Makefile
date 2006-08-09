#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1998-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
# lib/libldap4/spec/sparc/Makefile

.KEEP_STATE:

include	../Makefile.targ

# Add arch specific objects here
OBJECTS	+=

include	$(SRC)/lib/Makefile.lib

# Uncomment the following if the linker complains
sparc_C_PICFLAGS  = -K PIC

# To make sure the correct header files are located first
CPPFLAGS= -I$(SRC)/lib/libldap4/include $(CPPFLAGS.master)

include	$(SRC)/lib/Makefile.spec

install: $(ROOTABILIB)
