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
# cmd/lp/lib/access/Makefile
#

LIBRARY	=	liblpacc.a

OBJECTS =	allowed.o	\
		bang.o		\
		change.o	\
		dumpaccess.o	\
		files.o		\
		loadaccess.o

include		../../../../lib/Makefile.lib
include		../../Makefile.lp

# Specifically request the construction of a static library.
# This library is not installed in the proto area.
LIBS = $(LIBRARY)

CPPFLAGS =	-I../../include $(CPPFLAGS.master) $(C_PICFLAGS) -D_TS_ERRNO

POFILE =	lp_lib_access.po

.KEEP_STATE :

all install :	$(LIBS)

include		../../../../lib/Makefile.targ

CLEANFILES	+= llib-llpacc.ln
LINTFLAGS = -nvx
SRCS= $(OBJECTS:%.o=%.c)

lint:	lintlib
	$(LINT.c) $(LINTFLAGS) $(SRCS)

lintlib:
	$(LINT.c) $(LINTFLAGS) -o lpacc llib-llpacc

include		../Makefile.msg
