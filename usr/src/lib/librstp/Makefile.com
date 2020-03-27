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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =	librstp.a
VERS =		.1
OBJECTS =	edge.o migrate.o p2p.o pcost.o port.o portinfo.o rolesel.o \
		roletrns.o statmch.o stp_in.o stpm.o stpmgmt.o sttrans.o \
		times.o topoch.o transmit.o vector.o

include ../../Makefile.lib

LIBS =		$(DYNLIB)

SRCDIR =	../common
SRCS =		$(OBJECTS:%.o=$(SRCDIR)/%.c)


LDLIBS +=	-lc

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR) -D__SUN__ -D__STP_INTERNAL__

# not linted
SMATCH=off

.KEEP_STATE:

all: $(LIBS)


include ../../Makefile.targ
