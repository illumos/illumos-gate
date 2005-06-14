#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

include ../../Makefile.ctf

.KEEP_STATE:
.PARALLEL:

all:	libdwarf.so

install: all $(ROOTONBLDLIBMACH)/libdwarf.so.1

clean clobber:
	$(RM) libdwarf.so

FILEMODE	= 0755

%.so: %.so.1
	-$(RM) $@ ; \
	$(SYMLINK) ./$< $@

$(ROOTONBLDLIBMACH)/%: %
	$(INS.file)
