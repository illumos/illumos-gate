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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1993 by Sun Microsystems, Inc.
#


include ../Makefile.com


.KEEP_STATE:


DATAFILES64=		copyright depend
PACKAGE=		SUNWldv9
FILES64=		$(DATAFILES64) pkginfo
CLEANFILES64=		$(FILES64) awk_pkginfo ../bld_awk_pkginfo
CLOBBERFILES=		$(PACKAGE)


all: $(FILES64)
install: all .WAIT pkg


$(DATAFILES64): ../common/$$@
	$(RM) $@; cp ../common/$@ $@

pkginfo: pkginfo.tmpl awk_pkginfo
	$(RM) $@; nawk -f awk_pkginfo $@.tmpl > $@

pkg: FRC
	@rm -rf $(PACKAGE)
	pkgmk -f prototype -d $(PKGARCHIVE) -r $(ROOT) \
		-o $(PACKAGE) \
		2>&1 | grep -v "$(SRC)"
	pkgtrans -o -s . $(PACKAGE).tmp $(PACKAGE)
	rm -rf $(PACKAGE)
	mv $(PACKAGE).tmp $(PACKAGE)

awk_pkginfo:	../bld_awk_pkginfo
	../bld_awk_pkginfo -m $(MACH) -p "$(RELEASE)/$(VERSION)" -o $@

clean: FRC
	-$(RM) $(CLEANFILES64)

clobber: clean FRC
	-$(RM) -r $(CLOBBERFILES)

FRC:
