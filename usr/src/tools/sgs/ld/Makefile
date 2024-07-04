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

include		../../Makefile.tools
include		$(SRC)/cmd/sgs/ld/Makefile.com
include		../Makefile.com

LDLIBS =	-lumem -L../libconv -L$(ROOTONBLDLIBMACH64) -lld -lelf -lconv
NATIVE_LIBS +=	libc.so libumem.so
MAPFILES =	$(SRCDIR)/common/mapfile-intf
RPATH =		'-R$$ORIGIN/../../lib/$(MACH)/64'

include		$(SRC)/Makefile.master.64
include		$(SRC)/Makefile.native

install: $(ROOTONBLDMACH64PROG)

.KEEP_STATE:

include		$(SGSHOME)/ld/Makefile.targ
