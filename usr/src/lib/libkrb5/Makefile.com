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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# include library definitions
include $(SRC)/lib/Makefile.lib

LIBRARY =	libkrb5.a
LLIBRARY =	libkrb5.so.1
VERS =		.1

MAPFILES =	../common/mapfile $(MAPFILE.FLT)

DYNFLAGS +=	-G $(ZLOADFLTR)

LIBS =		$(DYNLIB)

#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

.KEEP_STATE:

all:	$(LIBS)

$(LIBS):	$(MAPFILES)
	$(LD) $(DYNFLAGS) -o $@


$(ROOTLIBDIR)/$(DYNLIB) :=	FILEMODE= 755
$(ROOTLIBDIR64)/$(DYNLIB) :=	FILEMODE= 755

$(ROOTLIBDIR)/%: %
	$(INS.file)
$(ROOTLIBDIR64)/%: %
	$(INS.file)

$(ROOTLIBDIR)/$(LIBLINKS): $(ROOTLIBDIR)/$(LIBLINKS)$(VERS)
	$(INS.liblink)
$(ROOTLIBDIR64)/$(LIBLINKS): $(ROOTLIBDIR64)/$(LIBLINKS)$(VERS)
	$(INS.liblink64)

clobber: clean
	-$(RM) $(CLOBBERTARGFILES)

clean:
	-$(RM) $(LIBS)

lint:
