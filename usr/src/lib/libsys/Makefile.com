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

LIBRARY=	libsys.a
VERS=		.1

COMOBJ=		libsys.o
OBJECTS=	$(COMOBJ)  $(MACHOBJ)

include 	../../../lib/Makefile.lib

MAPFILES =	mapfile-vers $(MAPFILE.FLT)

# Define libsys to be a filter on libc.  The ABI requires the runtime linker as
# the soname.

DYNFLAGS +=	-F/usr/lib/libc.so.1

SONAME=		/usr/lib/ld.so.1

# Redefine shared object build rule to use $(LD) directly (this avoids .init
# and .fini sections being added).

BUILD.SO=	$(LD) -o $@ -G $(DYNFLAGS) $(PICS)

pics/%.o :=	ASFLAGS += $(AS_PICFLAGS)

COMSRC=		$(COMOBJ:%.o=%.c)
MACHSRC=	$(MACHOBJ:%.o=%.s)

CLOBBERFILES +=	$(DYNLIB)  $(LIBLINKS)  $(COMSRC)  $(MACHSRC)
