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

include $(SRC)/lib/Makefile.lib
include $(SRC)/cmd/hal/Makefile.hal

CPPFLAGS =	$(HAL_DBUS_CPPFLAGS) $(HAL_GLIB_CPPFLAGS) $(CPPFLAGS.master)

ROOTLIBPCDIR =	$(ROOT)/usr/lib/pkgconfig
ROOTLIBPC =	$(LIBPCSRC:%=$(ROOTLIBPCDIR)/%)

CLOBBERFILES +=	$(LIBPCSRC)

#
# Ensure `all' is the default target.
#
all:

# no lint for 3rd party code
lint:

$(ROOTLIBPCDIR):
	$(INS.dir)

$(ROOTLIBPC): $(ROOTLIBPCDIR) $(LIBPCSRC)
	$(INS.file) $(LIBPCSRC)

$(LIBPCSRC): ../common/$(LIBPCSRC).in
	$(SED)	-e "s@__VERSION__@$(HAL_VERSION)@" \
		 < ../common/$(LIBPCSRC).in > $(LIBPCSRC)

