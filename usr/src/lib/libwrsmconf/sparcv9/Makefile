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
# Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../Makefile.com
include ../../Makefile.lib.64

CFLAGS64        += -erroff=E_STATEMENT_NOT_REACHED

BUILD.SO=	$(CC) $(CFLAGS64) -o $@ -G $(DYNFLAGS) $(OBJECTS) $(LDLIBS)

$(ROOTLIBDIR64):
	mkdir -p $(ROOTLIBDIR64)

$(ROOTLIBDIR64)/%: %
	$(INS.file)

$(ROOTLIBDIR64)/$(LIBLINKS): $(ROOTLIBDIR64)/$(LIBLINKS)$(VERS)
	$(INS.liblink64)

LINTFLAGS64 += -Xarch=v9

all:	$(LIBS)

install: all $(ROOTLIBDIR64) $(ROOTLIBS64) $(ROOTLINKS64)
