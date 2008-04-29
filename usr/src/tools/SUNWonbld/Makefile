#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
include ../../Makefile.master
include $(PKGDEFS)/Makefile.com
include ../Makefile.tools

LICENSEFILES += ../ctf/dwarf/THIRDPARTYLICENSE

.KEEP_STATE:

%: $(PKGDEFS)/%.ksh
	$(RM) $@
	cp $< $@
	chmod +x $@

all: awk_pkginfo $(FILES)

install: all .WAIT pkg

awk_pkginfo: bld_awk_pkginfo
	./bld_awk_pkginfo -m $(MACH) -p "$(RELEASE)/$(VERSION)" -o $@ -v \
	$(ONVERS)

pkginfo: pkginfo.tmpl awk_pkginfo
	$(RM) $@; nawk -f awk_pkginfo $@.tmpl > $@

pkg: $(FILES) $(PKGARCHIVE) FRC
	pkgmk -f prototype_$(MACH) -d $(PKGARCHIVE) -r $(TOOLS_PROTO) -o $(PACKAGE)

$(PKGARCHIVE):
	[ -d $(PKGARCHIVE) ] || mkdir -p $(PKGARCHIVE)

$(DATAFILES): $(PKGDEFS)/common_files/$$@
	$(RM) $@; cp $(PKGDEFS)/common_files/$@ $@

$(MACHDATAFILES): $(PKGDEFS)/common_files/$$@_$(MACH)
	$(RM) $@; cp $(PKGDEFS)/common_files/$@_$(MACH) $@

clobber clean:
	-$(RM) $(CLOBBERFILES) $(CLEANFILES)
	-$(RM) awk_pkginfo bld_awk_pkginfo

copyright: $(BUILDPKGCR) $(LICENSEFILES)
	@$(DO_BUILDPKGCR)

FRC:
