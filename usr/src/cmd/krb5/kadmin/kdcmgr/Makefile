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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=	kdcmgr
KLPROG=	klookup

OBJS=	klookup.o

SSRCS=	kdcmgr.sh
CSRCS=	$(OBJS:.o=.c)

include ../../../Makefile.cmd

POFILE=		$(SSRCS:%.sh=%.po)

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-uninitialized

LDLIBS	+=	-lresolv -lnsl

CLOBBERFILES +=	$(KLPROG)

.KEEP_STATE:

all: $(PROG) $(KLPROG)

KRB5LIBKLPROG=	$(KLPROG:%=$(KRB5LIB)/%)

install: $(PROG) $(KRB5SBINPROG) $(KRB5LIBKLPROG)

$(KLPROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

lint:
	$(LINT.c) $(CSRCS) $(LDLIBS)

clean:
	$(RM) $(OBJS)

include ../../../Makefile.targ
