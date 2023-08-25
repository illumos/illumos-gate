#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1989 by Sun Microsystems, Inc.
#
# Makefile for cmd/refer/papers
#

include		../../Makefile.cmd

ROOTDIRS =	$(ROOT)/usr/lib/refer/papers

PAPERS =	Rbstjissue runinv Rv7man
ROOTPAPERS =	$(PAPERS:%=$(ROOTDIRS)/%)


FILEMODE =	644

$(ROOTDIRS)/runinv := FILEMODE = 755

# install rule
$(ROOTDIRS)/% :	%
		$(INS.file)

.KEEP_STATE:

all :		$(PAPERS)

install: 	all $(ROOTDIRS) $(ROOTPAPERS)

$(ROOTDIRS) :
		$(INS.dir)

clean clobber strip:
