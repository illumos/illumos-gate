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

#
# The mech_dummy shared object contains all the functionality needed to
# support the Dummy GSS-API mechanism.
#

LIBRARY =	mech_dummy.a
VERS =		.1
OBJECTS =	dmech.o

include $(SRC)/lib/Makefile.lib

# There should be a mapfile here
MAPFILES =

CPPFLAGS +=	-I../../libgss -I$(SRC)/uts/common/gssapi/include \
	    	-I$(ROOT)/usr/include/gssapi

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized

SRCDIR =	../mech
LIBS =		$(DYNLIB)
LDLIBS +=	-lgss -lc

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include $(SRC)/lib/Makefile.targ
