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
# Makefile.filter.com and Makefile.filter.targ provide centralized Makefiles
# for driving the creation of standard shared object filters.  This class of
# filter contains absolutely no implementation (code), instead associating all
# symbol definitions to an alternative shared object (filtee).
#
# Standard filters are commonly used to preserve previously documented system
# interfaces when moving symbol definitions from one library to another.  They
# are analogous to the way symbolic links are used in the system to preserve
# well known file names.  For example, the Unified Process Model folded threads
# processing into libc.so.1, and left standard filters /lib/lib[p]thread.so.1
# in place.  These filters are built under usr/src/lib/lib[p]thread, and serve
# as typical examples.
#
# A typical Makefile.com for building a standard filter library contains:
#
#   % cat Makefile.com
#   ...
#   LIBRARY =	   libxxxx.a
#   VERS =	   .1
#
#   include	   $(SRC)/lib/Makefile.rootfs		(1)
#
#   DYNFLAGS +=	   -F filtee				(2)
#   MAPFILEDIR =   .					(3)
#
# 1.  Use Makefile.rootfs when destination is /lib (rather than /usr/lib).
# 2.  Customize DYNFLAGS to indicate filtee name.
# 3.  Change MAPFILEDIR if mapfiles are not under ../common.
#
# The typical use of Makefile.filter.com and Makefile.filter.targ is through
# inclusion from a standard filters machine specific Makefiles:
#
#   % cat $(MACH)/Makefile
#   ...
#   include	   $(SRC)/lib/Makefile.filter.com
#   include	   ../Makefile.com
#   include	   (SRC)/lib/Makefile.lib.64		(1)
#
#   DYNFLAGS +=	   -h libyyyyy.so.1			(2)
#
#   install	   all $(ROOT......
#
#   include	   $(SRC)/lib/Makefile.filter.targ
#
# 1.  Use Makefile.lib.64 for 64-bit builds.
# 2.  Customize DYNFLAGS for $MACH if necessary.
#

include		$(SRC)/lib/Makefile.lib

# Define common flags, that override or append to Makefile.lib rules.

DYNFLAGS +=	$(ZNODUMP) $(ZNOLDYNSYM)
LIBS =		$(DYNLIB)
SRCDIR =	../common
MAPFILES +=	$(MAPFILE.FLT)
