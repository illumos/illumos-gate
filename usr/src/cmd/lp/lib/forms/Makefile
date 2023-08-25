#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/lp/lib/forms/Makefile
#

LIBRARY	=	liblpfrm.a

OBJECTS	=	delform.o	\
		f_head.o	\
		freeform.o	\
		getform.o	\
		putform.o	\
		rdform.o	\
		wrform.o


include		../../../../lib/Makefile.lib
include         ../../Makefile.lp

# Specifically request the construction of a static library.
# This library is not installed in the proto area.
LIBS = $(LIBRARY)

CFLAGS +=	$(C_BIGPICFLAGS)
CPPFLAGS =	-I../../include $(CPPFLAGS.master)

POFILE =	lp_lib_forms.po

.KEEP_STATE:

all install :	$(LIBS)

include		../../../../lib/Makefile.targ

CLEANFILES	+= llib-llpfrm.ln
LINTFLAGS = -nvx
SRCS= $(OBJECTS:%.o=%.c)

lint:	lintcheck

lintlib:
	$(LINT.c) $(LINTFLAGS) -o lpfrm llib-llpfrm

include		../Makefile.msg
