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
# Copyright (c) 1996 by Sun Microsystems, Inc.
# All rights reserved.

include		../Makefile.com
include		../../Makefile.tools
include		$(SGSHOME)/ld/Makefile.com

LDLIBS =	-L../libconv -L$(ROOTONBLDLIBMACH) -lld -lelf -lconv
NATIVE_LIBS +=	libc.so
CPPFLAGS =	$(NATIVE_CPPFLAGS)
CFLAGS =	$(NATIVE_CFLAGS)
MAPFILES =	$(SRCDIR)/common/mapfile-intf
CW_LINKER =
VAR_LD_LLDFLAGS=	'-R$$ORIGIN/../../lib/$(MACH)'
VAR_LD_LLDFLAGS64 =	'-R$$ORIGIN/../../../lib/$(MACH64)'

install: $(ROOTONBLDMACHPROG)

.KEEP_STATE:

include		$(SGSHOME)/ld/Makefile.targ
