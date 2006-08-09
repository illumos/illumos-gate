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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY=	libdbm.a
VERS=		.1

OBJECTS= dbm.o

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOTLIBDIR=	$(ROOT)/usr/ucblib
ROOTLIBDIR64=	$(ROOT)/usr/ucblib/$(MACH64)

LIBS = $(DYNLIB) $(LINTLIB)

LINTSRC= $(LINTLIB:%.ln=%)
ROOTLINTDIR= $(ROOTLIBDIR)
ROOTLINTDIR64= $(ROOTLIBDIR)/$(MACH64)
ROOTLINT= $(LINTSRC:%=$(ROOTLINTDIR)/%)
ROOTLINT64= $(LINTSRC:%=$(ROOTLINTDIR64)/%)

# install rule for lint source file target
$(ROOTLINTDIR)/%: ../%
	$(INS.file)
$(ROOTLINTDIR64)/%: ../%
	$(INS.file)

$(LINTLIB):= SRCS=../llib-ldbm

CFLAGS	+=	$(CCVERBOSE)
LDLIBS +=	-lc

CPPFLAGS = -I$(ROOT)/usr/ucbinclude $(CPPFLAGS.master)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

#
# Include library targets
#
include $(SRC)/lib/Makefile.targ

objs/%.o pics/%.o: ../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
