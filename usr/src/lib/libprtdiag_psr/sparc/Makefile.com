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
# Copyright 2020 Peter Tribble.
#

LIBRARY= libprtdiag_psr.a
VERS= .1

#
# PSR_MACH is defined sun4u so previous sun4u platforms can still continue
# to use sun4u libraries but sun4v platforms can override it to use sun4v
# libraries.
#
PSR_MACH= sun4u
#
# PLATFORM_OBJECTS is defined in ./desktop ./wgs Makefiles
#
OBJECTS= $(PLATFORM_OBJECTS)

# include library definitions
include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm

SRCS=		$(OBJECTS:%.o=./common/%.c)

LIBS = $(DYNLIB)

# There should be a mapfile here
MAPFILES =

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-value
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-address
IFLAGS +=	-I $(UTSBASE)/sun4u
IFLAGS +=	-I $(UTSCLOSED)/sun4u
CPPFLAGS =	$(IFLAGS) $(CPPFLAGS.master)
LDLIBS +=	-L $(ROOT)/usr/platform/$(PSR_MACH)/lib -lprtdiag -lc
DYNFLAGS +=	-R /usr/platform/$(PSR_MACH)/lib
INS.slink6=	$(RM) -r $@; $(SYMLINK) ../../$(PLATFORM)/lib/libprtdiag_psr.so.1 $@

.KEEP_STATE:

all: $(LIBS)


# include library targets
include $(SRC)/lib/Makefile.targ

objs/%.o pics/%.o: ./common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
