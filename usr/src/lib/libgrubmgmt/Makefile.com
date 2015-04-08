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
# Copyright 2015 Toomas Soome <tsoome@me.com>
#
#

LIBRARY =	libgrubmgmt.a
VERS =		.1
OBJECTS =	libgrub_cmd.o libgrub_entry.o libgrub_fs.o
OBJECTS +=	libgrub_menu.o libgrub_bargs.o libgrub_errno.o

include ../../Makefile.lib
include ../../Makefile.rootfs

LIBS =		$(DYNLIB) $(LINTLIB)

SRCDIR = ../common

INCS += -I$(SRCDIR)

$(LINTLIB) :=	SRCS =	$(SRCDIR)/$(LINTSRC)
#
# Libraries added to the next line must be present in miniroot
#
LDLIBS +=	-lc -lzfs -ldevinfo -lfstyp -lefi

CFLAGS +=	$(CCVERBOSE)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ
