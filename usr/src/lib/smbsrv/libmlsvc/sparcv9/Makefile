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

MACH_LDLIBS +=	-L$(ROOT)/usr/lib/smbsrv/$(MACH64)

include ../Makefile.com
include ../../../Makefile.lib.64

# With the adition of BIND 8.3.3, the symbol table for 64 bit went over
# the limit for Kpic, so we add -KPIC here, for just the 64 bit SPARC
# library. This avoids compiling the 32-bit library with PIC unnecessarily.
sparcv9_C_PICFLAGS =	$(sparcv9_C_BIGPICFLAGS)

DYNFLAGS +=	-R/usr/lib/smbsrv/$(MACH64)

install: all $(ROOTLIBS64) $(ROOTLINKS64)
