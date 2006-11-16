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

LIBRARY =	bsd_test.a
VERS=.1

OBJECTS =	test.o

include		../../../../../lib/Makefile.lib
include         ../../../Makefile.sp

# There should be a mapfile here
MAPFILES =

ROOTLIBDIR=	$(ROOT)/usr/lib/print/bsd-adaptor

#CPPFLAGS +=	-I$(LPINC)
CPPFLAGS +=	-I$(NPRTINC)
LDLIBS +=	-lprint -lc		# with XFN API
#LDLIBS +=	$(LIBCLS) $(LIBPRT) $(LIBMSG)

LIBS = $(DYNLIB)	# could be += for static and dynamic
SRCS= $(OBJECTS:%.o=%.c)

CLOBBERFILES=	llib-lbsd_test.a.ln lint.out
 
.KEEP_STATE:
  
all :	$(LIBS)

install:	$(ROOTLIBDIR) $(ROOTLIBS) $(ROOTLINKS)

cstyle:
	cstyle $(SRCS)

lint:
	$(LINT.c) $(SRCS)
strip:

_msg:
	@echo "Messages are made in usr/src/cmd/print"

$(ROOTLIBDIR):
	$(INS.dir)

include		../../../../../lib/Makefile.targ
