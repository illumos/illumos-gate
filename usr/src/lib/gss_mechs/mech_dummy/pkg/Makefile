#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 1997, 2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

# from usr/src/pkgdefs/Makefile.com :

include $(SRC)/Makefile.master

PKGARCHIVE=$(SRC)/../../pkgarchive/$(MACH)/$(RELEASE)
DATAFILES=copyright
FILES=$(DATAFILES) pkginfo

PACKAGE=gssdummy

CLOBBERFILES= $(FILES)

DATAFILES += depend

ACTION_SUNWgss=grep SUNWgss depend > /dev/null || \
	( chmod 666 depend; \
	echo "P SUNWgss	gss" >> depend; \
	chmod 444 depend );

.KEEP_STATE:

all: $(FILES) action

install: all gather pkg

gather:
	sh getfiles

# action is a pseudotarget denoting completed work on the depend file
action: depend
	$(ACTION_SUNWgss)
	touch $@

# from usr/src/pkgdefs/Makefile.targ :

pkginfo: pkginfo.tmpl $(SRC)/pkgdefs/awk_pkginfo
	$(RM) $@; nawk -f $(SRC)/pkgdefs/awk_pkginfo $@.tmpl > $@

pkg: $(PKGARCHIVE) FRC
	pkgmk -f prototype_$(MACH) -d $(PKGARCHIVE) -r `basename $(ROOT)` \
		-o $(PACKAGE)

$(PKGARCHIVE):
	[ -d $(PKGARCHIVE) ] || mkdir -p $(PKGARCHIVE)

$(DATAFILES): $(SRC)/pkgdefs/common_files/$$@
	$(RM) $@; cp $(SRC)/pkgdefs/common_files/$@ $@

$(MACHDATAFILES): $(SRC)/pkgdefs/common_files/$$@_$(MACH)
	$(RM) $@; cp $(SRC)/pkgdefs/common_files/$@_$(MACH) $@

clobber clean:
	-$(RM) $(CLOBBERFILES) $(CLEANFILES)

FRC:
