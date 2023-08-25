#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1989 by Sun Microsystems, Inc.
#
# cmd/bnu/Makefile
#

include			../../Makefile.cmd

FILES =			eqnchar iso ascii greek

ROOTSHPUB =		$(ROOTSHLIB)/pub

ROOTSHPUBFILES =	$(FILES:%=$(ROOTSHPUB)/%)


FILEMODE =		644

.KEEP_STATE :

all :			$(FILES)

install :		$(ROOTSHPUB) $(ROOTSHPUBFILES)

clean clobber strip lint:

$(ROOTSHPUB) :
			$(INS.dir)

$(ROOTSHPUB)/% :	%
			$(INS.file)
