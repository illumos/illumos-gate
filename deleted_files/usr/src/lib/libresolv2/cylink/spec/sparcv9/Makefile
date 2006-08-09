#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.
#
# lib/libresolv2/cylink/spec/sparcv9/Makefile

.KEEP_STATE:

include	../Makefile.targ

# Add arch specific objects here
OBJECTS	+=

include	$(SRC)/lib/Makefile.lib
include	$(SRC)/lib/Makefile.lib.64

# Uncomment the following if the linker complains
#sparcv9_C_PICFLAGS  = -K PIC

include	$(SRC)/lib/Makefile.spec

# No public interface, so don't install spec libraries in the proto area
INS.abilib=

install: $(ROOTABILIB64)
