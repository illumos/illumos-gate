#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

.KEEP_STATE:

include	../Makefile.targ

# Add arch specific objects here
OBJECTS	+=

include	$(SRC)/lib/Makefile.lib
include	$(SRC)/lib/Makefile.lib.64

# Uncomment the following if the linker complains
#amd64_C_PICFLAGS  = -K PIC

# To make sure the correct header files are located first
CPPFLAGS= -I$(SRC)/lib/libldap4/include $(CPPFLAGS.master)

include	$(SRC)/lib/Makefile.spec

install: $(ROOTABILIB64)
