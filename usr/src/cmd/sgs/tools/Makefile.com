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
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.

#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Makefile to support tools used for linker development:
#
# piglatin	- generates phone message catalogs for testing
#

# Note, these tools are not part of the product.
#
# cmd/sgs/tools/Makefile.com

include		$(SRC)/cmd/Makefile.cmd

include		$(SRC)/cmd/sgs/Makefile.com

OBJECTS=	piglatin.o
NATIVECC_CFLAGS = -O
NATIVE_LDFLAGS = $(LDASSERTS) $(ZASSERTDEFLIB)=libc.so $(BDIRECT)

NATIVE=		$(OBJECTS:%.o=%)
SRCS=		$(OBJECTS:%.o=../common/%.c)

CPPFLAGS +=	$(VAR_TOOLS_CPPFLAGS)

ROOTDIR=	$(ROOT)/opt/SUNWonld
ROOTPROGS=	$(PROGS:%=$(ROOTDIR)/bin/%)

FILEMODE=	0755

# not linted
SMATCH=off
