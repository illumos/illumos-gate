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
#ident	"%Z%%M%	%I%	%E% SMI"
#

include ../../../../Makefile.cmd
include ../../../../Makefile.cmd.64
include ../../Makefile.sparcv9
include ../../Makefile.kmdb.64
include ../../../Makefile.kmdb

STANDLIBS += $(ROOT)/usr/lib/sparcv9/libstanddisasm.so

all:	kmdb_modlinktest.o
lint:	FRC

#
# Uncomment the following line to enable trap accounting.  A DTLB translation
# will be added for the trap table, and each handler installed by KMDB will use
# its padding to keep a trap count.  See kaif_handlers.s.
#
#TRAPCOUNT = -DKMDB_TRAPCOUNT

CPPFLAGS += -I../../mdb -I.. -I$(SRC)/uts/sun4 -I$(SRC)/uts/sun4u $(TRAPCOUNT)
ASFLAGS += -I$(SRC)/uts/sun4 -I$(SRC)/uts/sun4u $(TRAPCOUNT)

install: all

FRC:
