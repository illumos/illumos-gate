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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Platform specific Makefile for the prtdiag command.
#
# PLATFORM is the target for the binary installation.
#
# PLATLINKS is a list of platforms which are to be linked to this binary
#	at the file level.

SRCDIR		= ../..
PLATFORM	= sun4u
PLATLINKS	=

include $(SRCDIR)/Makefile.com

CFLAGS		+= -R /usr/platform/$(PLATFORM)/lib

LDLIBS		+= -L $(ROOT)/usr/platform/$(PLATFORM)/lib
LDLIBS		+= -lprtdiag
LINTFLAGS	+= -u

.KEEP_STATE:

all:	$(LIBPRTDIAG) $(PROG)

include $(SRCDIR)/sparc/Makefile.targ
