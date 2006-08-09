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
# ident	"%Z%%M%	%I%	%E% SMI"
#

4VERS=		.0

include		../Makefile.com

DYNFLAGS +=	-F /usr/lib/ld.so.1

# A symbolic link from /usr/4lib/libdl.so.1.0 is required for BCP.

4DYNLIB=	libdl.so.1$(4VERS)
ROOT4LIBDIR=	$(ROOT)/usr/4lib
ROOT4LINKS=	$(ROOT4LIBDIR)/$(4DYNLIB)
$(ROOT4LINKS):=	LIBLINKPATH = $(VAR_LIBDL_ROOT4LINK_LIBLINKPATH)

.KEEP_STATE:

include		../Makefile.targ

all:		$(DYNLIB) $(LINTLIB)

install:	all $(ROOTFS_DYNLIB) $(VAR_LIBDL_ETCDYNLIB) \
		$(ROOTFS_LINKS) $(ROOT4LINKS) \
		$(ROOTFS_LINTLIB) $(ROOTFS_LIBDIR)/$(LINTLIBSRC)

$(VAR_POUND_1)$(ROOTFS_LIBDIR)/$(LINTLIBSRC): ../common/$(LINTLIBSRC)
$(VAR_POUND_1)	$(INS.file) ../common/$(LINTLIBSRC)

$(ROOT4LINKS):	$(ROOTFS_DYNLIB)
	$(INS.liblink)
