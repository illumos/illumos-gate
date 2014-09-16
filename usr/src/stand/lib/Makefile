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
# Copyright 2014 Gary Mills
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include Makefile.com

i386_SUBDIRS =
sparc_SUBDIRS =
SUBDIRS = fakeboot fs/hsfs fs/nfs fs/ufs inet sa sock tcpstubs xdr \
	tcp $($(MACH)_SUBDIRS)

#
# Don't lint fakeboot since it doesn't have any source files.
#
LINTSUBDIRS = $(SUBDIRS:fakeboot=)

#
# We can get away with this since we're only building .a's, and by the
# time we run lint all of the lint libraries have already been built.
#
.PARALLEL: $(SUBDIRS)

.KEEP_STATE:

all	:=	TARGET = all
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber
install	:=	TARGET = install
lint	:=	TARGET = lint

all clean clobber install: $(SUBDIRS)

lint: $(LINTSUBDIRS)

#
# The reason this rule checks for the existence of the
# Makefile is that some of the directories do not exist
# in our exportable source builds.
#
$(SUBDIRS): FRC
	@if [ -f $@/Makefile  ]; then \
		cd $@; pwd; $(MAKE) $(TARGET); \
	else \
		true; \
	fi

FRC:

#
# Cross-reference customization: set the include path to be reasonable.
#
XRINCDIRS = $(CPPINCS:-YI,%=-I%)
