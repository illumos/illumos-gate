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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

PROG=		parted

include		../Makefile.cmd

C99MODE=	$(C99_ENABLE)
CERRWARN +=	-erroff=E_EXTERN_INLINE_UNDEFINED
CERRWARN +=	-erroff=E_ARG_INCOMPATIBLE_WITH_ARG
CERRWARN +=	-_gcc=-Wno-unused-function

srcdir=	.

CPPFLAGS +=	-I. \
		-I../../lib/libparted/common/lib \
		-I../../lib/libparted/common/include

ARFLAGS=	cq

OBJS=		command.o parted.o strlist.o table.o ui.o

SRCS=		$(OBJS:%.o=$(srcdir)/%.c)

LDLIBS +=	../../lib/libparted/i386/libparted.so.8 

ROOTPROG=	$(PROG:%=$(ROOTUSRSBIN)/%)

.KEEP_STATE:
all: $(PROG)

all install: THIRDPARTYLICENSE

CLOBBERFILES += THIRDPARTYLICENSE

THIRDPARTYLICENSE: $(SRC)/common/GPLDISCLAIMER COPYING
	$(RM) $@
	$(CAT) $(SRC)/common/GPLDISCLAIMER COPYING > $@

$(PROG):	$(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install:	all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

#
# This open source is exempted from lint
#
lint:

include		../Makefile.targ
