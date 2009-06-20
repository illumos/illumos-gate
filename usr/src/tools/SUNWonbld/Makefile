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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../../Makefile.master
include $(PKGDEFS)/Makefile.com
include ../Makefile.tools

#
# Warning: do not use the common license files here.  Instead, make sure
# that all files listed in LICENSEFILES come from somewhere under the
# usr/src/tools directory, have a corresponding .descrip file, and have a
# corresponding entry in usr/src/tools/opensolaris/license-list.
#
# If they only apply to source under usr/src/tools, simply integrate
# the licenses as source-code-managed text files, as with the dwarf
# license referenced below.
#
# If the licenses are duplicated in other parts of the source tree,
# create a Makefile target to copy them into place, as is done in
# usr/src/tools/onbld/Makefile for the onbld license referenced below.
#
# This dance ensures that the appropriate licenses are incorporated into
# both the package copyright file and the tools tarball license file.
# See usr/src/tools/scripts/mktpl.pl for details.
#
LICENSEFILES += \
	../ctf/dwarf/THIRDPARTYLICENSE \
	../onbld/THIRDPARTYLICENSE

CLEANFILES += bld_awk_pkginfo

CLOBBERFILES += awk_pkginfo

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

clean:
	-$(RM) $(CLEANFILES)

clobber: clean
	-$(RM) $(CLOBBERFILES)

copyright: $(BUILDPKGCR) $(LICENSEFILES)
	@$(DO_BUILDPKGCR)

FRC:
