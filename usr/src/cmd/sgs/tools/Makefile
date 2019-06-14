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
# Makefile to support tools used for linker development.  GEXECS are those
# tools that the installed for distribution in the SUNWonld package.
#
#  o	`c' programs are built from the $(MACH)/Makefile
#
#  o	info: summarizes relocation overhead, and a sorted string listing.
#
#  o	proto: creates a proto directory structure suitable for sgs make
#	installs (basically a subset of Targetdirs).

#
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

include		$(SRC)/Makefile.master

SUBDIRS=	$(MACH)

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber


.KEEP_STATE:

all install clean clobberall: $(SUBDIRS)

delete:

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
