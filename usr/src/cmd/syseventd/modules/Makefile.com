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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Common prologue for Makefiles for all sysevent loadable .so modules
#

SRCS =		$(LIBRARY:%=%.c)
OBJECTS =	$(LIBRARY:%=%.o)

include $(SRC)/lib/Makefile.lib
include $(SRC)/cmd/syseventd/Makefile.com

SRCDIR =	.
HSONAME =
MAPFILES =	$(SRC)/cmd/syseventd/modules/mapfile-extern

#
# sysevent loadable modules require sysevent header files
#
CPPFLAGS += -I ../../daemons/syseventd
LDLIBS +=	-lc

POFILES =	$(SRCS:.c=.po)
POFILE =	$(LIBRARY).po

CLOBBERFILES += $(LIBRARY)
