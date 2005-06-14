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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1993,1998 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/eeprom/Makefile.com
#

#
#	Create default so empty rules don't
#	confuse make
#
CLASS		= 32

include $(SRCDIR)/../Makefile.cmd
include $(SRCDIR)/../../Makefile.psm

PROG		= eeprom

FILEMODE	= 02555
DIRMODE		= 755
GROUP		= sys

#
# Sparc program implementation supports openprom machines.  identical versions
# are installed in /usr/platform for each machine type
# because (at this point in time) we have no guarantee that a common version
# will be available for all potential sparc machines (eg: ICL, solbourne ,...).
#
# The identical binary is installed several times (rather than linking them
# together) because they will be in separate packages.
#
# Now that it should be obvious that little (if anything) was gained from
# this `fix-impl' implementation style, maybe somebody will unroll this in
# distinct, small and simpler versions for each PROM type.
#
IMPL = $(PLATFORM:sun%=sun)

prep_OBJS = openprom.o loadlogo.o
sun_OBJS = openprom.o loadlogo.o
i86pc_OBJS = benv.o benv_kvm.o benv_sync.o
OBJS = error.o
OBJS += $($(IMPL)_OBJS)
LINT_OBJS = $(OBJS:%.o=%.ln)

prep_SOURCES = openprom.c loadlogo.c
sun_SOURCES = openprom.c loadlogo.c
i86pc_SOURCES = benv.c benv_kvm.c benv_syn.c
SOURCES	= error.c
SOURCES	+= $($(IMPL)_SOURCES)

.PARALLEL: $(OBJS)

%.o:	../common/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(SRCDIR)/common/%.c
	$(COMPILE.c) -o $@ $<

%.ln:	../common/%.c
	$(LINT.c) -c $@ $<

%.ln:	$(SRCDIR)/common/%.c
	$(LINT.c) -c $@ $<
