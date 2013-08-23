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
# Copyright 1993,1998,2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/backup/Makefile
#

include Makefile.backup

COMMONPRODSUBDIRS=	dump restore
UFSPRODSUBDIRS=
LIBSUBDIRS=	lib
LIBDONE=	$(LIBSUBDIRS)/.target_done
SUBDIRS=	$(LIBSUBDIRS) $(COMMONPRODSUBDIRS) $(UFSPRODSUBDIRS)
UFSSUBDIRS=	$(LIBSUBDIRS) $(COMMONPRODSUBDIRS) $(UFSPRODSUBDIRS)

UFSINSDIRS=	$(UFSROOTETC) $(UFSROOTUSR) $(UFSROOTUSRLIB) \
		$(UFSROOTUSRLIBFS) $(UFSROOTUSRSBIN)
PODIRS=		dump restore

.KEEP_STATE:

.DONE:
	@rm -f $(LIBDONE)

all debug lint check: $(COMMONPRODSUBDIRS) $(UFSPRODSUBDIRS)

_msg:	$(PODIRS)

clean clobber: $(SUBDIRS) .DONE

install:	$(UFSINSDIRS) $(UFSSUBDIRS)

$(UFSINSDIRS):
	$(INS.dir)

$(COMMONPRODSUBDIRS) $(UFSPRODSUBDIRS): $(LIBSUBDIRS) FRC
	$(DO_SUBDIR)

$(LIBSUBDIRS): FRC
	$(DO_SUBDIR)

FRC:
