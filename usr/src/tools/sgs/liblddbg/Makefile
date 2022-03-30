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

include		../Makefile.com
include		../../Makefile.tools
include		$(SGSHOME)/liblddbg/Makefile.com
include		$(SRC)/Makefile.master.64

.KEEP_STATE:

CPPFLAGS =	$(NATIVE_CPPFLAGS) -I$(SRC)/lib/libc/inc
CFLAGS =	$(NATIVE_CFLAGS)
DYNFLAGS +=	-L../libconv
SGSMSGTARG +=	$(SGSMSG32)
NATIVE_LIBS +=	libc.so
CW_LINKER =

# A bootstrapping problem means we can't use the regular mapfile just yet
MAPFILES =

all:		$(DYNLIB) $(LIBLINKS)

install:	all $(ROOTONBLDLIBMACH64)/$(DYNLIB) $(ROOTONBLDLIBMACH64)/$(LIBLINKS)

$(ROOTONBLDLIBMACH64)/$(DYNLIB): $(PICS) $(ROOTONBLDLIBMACH64)
		$(BUILD.SO)
		$(POST_PROCESS_SO)

$(ROOTONBLDLIBMACH64)/$(LIBLINKS): $(ROOTONBLDLIBMACH64)/$(DYNLIB)
		@$(RM) $(ROOTONBLDLIBMACH64)/$(LIBLINKS)
		$(SYMLINK) $(DYNLIB) $(ROOTONBLDLIBMACH64)/$(LIBLINKS)

include		$(SGSHOME)/liblddbg/Makefile.targ
