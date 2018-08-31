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
# Copyright 2018 Joyent, Inc.
#
LIBRARY=	libdevid.a
VERS=		.1
OBJECTS=	deviceid.o devid.o devid_scsi.o devid_smp.o

include ../../Makefile.lib
include ../../Makefile.rootfs

SRCS =		../deviceid.c $(SRC)/common/devid/devid.c \
		$(SRC)/common/devid/devid_scsi.c \
		$(SRC)/common/devid/devid_smp.c
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)
LIBS =		$(DYNLIB) $(LINTLIB)
#
# Libraries added to the next line must be present in miniroot
#
LDLIBS +=	-ldevinfo -lc

CFLAGS +=	$(CCVERBOSE)

CSTD =	$(CSTD_GNU99)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ

pics/devid.o:	 $(SRC)/common/devid/devid.c
	$(COMPILE.c) -o $@ $(SRC)/common/devid/devid.c
	$(POST_PROCESS_O)

pics/devid_scsi.o:	 $(SRC)/common/devid/devid_scsi.c
	$(COMPILE.c) -o $@ $(SRC)/common/devid/devid_scsi.c
	$(POST_PROCESS_O)

pics/devid_smp.o:	 $(SRC)/common/devid/devid_smp.c
	$(COMPILE.c) -o $@ $(SRC)/common/devid/devid_smp.c
	$(POST_PROCESS_O)
