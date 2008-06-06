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
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY = c_synonyms.a
VERS = .1

OBJECTS = synonyms.o

include ../../Makefile.lib
include ../../Makefile.rootfs

LIBS 		 = $(DYNLIB)
LDLIBS 		+= -lc

BUILD.SO =	$(LD) -o $@ -G $(DYNFLAGS) $(PICS) $(LDLIBS)

CLEANFILES += synonym_list mapfile-vers

.KEEP_STATE:

all: $(LIBS)

pics/synonyms.o:	pics .WAIT synonym_list

synonym_list:	../syn_common ../syn2_common syn_isa
	$(CAT) ../syn_common syn_isa | \
		$(SED) -e '/^#/d' -e '/^$$/d' -e 's/.*/	SYN(&)/' >synonym_list
	$(CAT) ../syn2_common | \
		$(SED) -e '/^#/d' -e '/^$$/d' -e 's/.*/	SYN2(&)/' >>synonym_list

$(DYNLIB):	mapfile-vers $(PICS)

mapfile-vers:	../syn_common ../syn2_common syn_isa
	echo "SUNWprivate_1.1 {\n    global:" >mapfile-vers
	$(CAT) ../syn_common syn_isa | \
		$(SED) -e '/^#/d' -e '/^$$/d' -e 's/.*/	_&;/' >>mapfile-vers
	$(CAT) ../syn2_common | \
		$(SED) -e '/^#/d' -e '/^$$/d' -e 's/.*/	__&;/' >>mapfile-vers
	echo "    local:\n	*;\n};" >>mapfile-vers

BUILD.s=	$(AS) $(ASFLAGS) $< -o $@

# include library targets
include ../../Makefile.targ

MAPFILES =	mapfile-vers

pics/%.o:	%.s
	$(BUILD.s)
