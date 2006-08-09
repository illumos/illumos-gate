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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/Makefile.spec

.KEEP_STATE:

#
# This file depends on the macro $(OBJECTS) containing a .o file for every
# spec file and $(SRC)/usr/lib/Makefile.lib(.64) being included.
#
SPECTRANS=	$(SRC)/cmd/abi/spectrans
#
# If the shell variable SPECWS is defined the spectrans tools from the current
# workspace will be used
#
SPECWS=	$(POUND_SIGN)

ABILIBDIR=	$($(TRANSMACH)_ABILIBDIR)

# Map OBJECTS to .spec files
SPECS=		$(OBJECTS:%.o=../%.spec)

# Name of shared object to actually build
ABILNROOT=	$(LIBRARY:%.a=%)

# Where to find spec files that this spec may depend on
TRANSCPP +=	-I$(SRC)/lib
# Fall back to parent workspace if spec file is not in this Workspace
TRANSCPP +=	$(ENVCPPFLAGS2:%/proto/root_$(MACH)/usr/include=%/usr/src/lib)
TRANSFLAGS=	-a $(TRANSMACH) -l $(ABILNROOT) $(TRANSCPP)
SPEC2MAP_FLAGS= -p

SPECMAP=	mapfile$(SPECVERS)
VERSFILE=	../versions$(SPECVERS)

CLEANFILES +=	$(SRCS)
CLOBBERFILES +=	$(SPECMAP)

SPEC2MAP=	/usr/lib/abi/spec2map
$(SPECWS)SPEC2MAP=	$(SPECTRANS)/spec2map/$(MACH)/spec2map

all install:		$(SPECMAP)

$(SPECMAP):	$(VERSFILE) $(SPECS)
	$(SPEC2MAP) $(SPEC2MAP_FLAGS) $(TRANSFLAGS) -v $(VERSFILE) \
	-o $@ $(SPECS) \

# We define the following two targets (clean, and clobber)
# instead of inheriting them from Makefile.targ to avoid inheriting the
# other rules which cause incremental build failures
clean:
	-$(RM) $(OBJS) $(CLEANFILES)

clobber: clean
	-$(RM) $(CLOBBERFILES)

FRC:
