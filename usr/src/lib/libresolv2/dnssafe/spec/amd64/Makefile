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
#amd64_C_PICFLAGS = $(amd64_C_BIGPICFLAGS)

include	$(SRC)/lib/Makefile.spec

# No public interface, so don't install spec libraries in the proto area
INS.abilib=

install: $(ROOTABILIB64)
