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
# Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
#

include		../../Makefile.tools
include		$(SRC)/cmd/sgs/libelf/Makefile.com
include		../Makefile.com

CONVLIBDIR =	-L../libconv
SGSMSGTARG +=	$(SGSMSG32)
NATIVE_LIBS +=	libc.so

CPPFLAGS +=	-I$(SRC)/cmd/sgs/libelf/common
LDLIBS +=	$(CONVLIBDIR) -lconv

include		$(SRC)/Makefile.native
include		$(SRC)/Makefile.master.64

# As a bootstrapping issue, we can't use the real mapfile because we build
# early in tools and thus don't have support for assertions.
MAPFILES=

.KEEP_STATE:

install:	all $(ROOTONBLDLIBMACH64)/$(DYNLIB) \
	$(ROOTONBLDLIBMACH64)/$(LIBLINKS)

$(ROOTONBLDLIBMACH64)/$(DYNLIB): $(PICS) $(ROOTONBLDLIBMACH64)
		$(BUILD.SO)
		$(POST_PROCESS_SO)

$(ROOTONBLDLIBMACH64)/$(LIBLINKS): $(ROOTONBLDLIBMACH64)/$(DYNLIB)
		@$(RM) $(ROOTONBLDLIBMACH64)/$(LIBLINKS)
		$(SYMLINK) $(DYNLIB) $(ROOTONBLDLIBMACH64)/$(LIBLINKS)

include		$(SGSHOME)/libelf/Makefile.targ
