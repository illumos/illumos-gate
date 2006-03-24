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

LIBRARY =	bsd_lpsched.a
VERS=.1

OBJECTS =	show_queue.o cancel_job.o submit_job.o misc.o

include		../../../../lib/Makefile.lib
include         ../../Makefile.lp

ROOTLIBDIR=	$(ROOT)/usr/lib/print/bsd-adaptor

CPPFLAGS +=	-I$(LPINC)
CPPFLAGS +=	-I$(SRC)/lib
LDLIBS +=	-lprint -z lazyload -ltsol -z nolazyload -lc
LDLIBS	+=	-L$(SRC)/cmd/lp/lib/msgs -llpmsg
LDLIBS	+=	-L$(SRC)/cmd/lp/lib/class -llpcls
LDLIBS	+=	-L$(SRC)/cmd/lp/lib/lp -llp
LDLIBS	+=	-L$(SRC)/cmd/lp/lib/requests -llpreq
LDLIBS	+=	-L$(SRC)/cmd/lp/lib/secure -llpsec


LIBS = $(DYNLIB)
SRCS= $(OBJECTS:%.o=%.c)

POFILE=		lp_cmd_adaptor.po
OBJS=		$(OBJECTS)

.KEEP_STATE:
  
all:	$(LIBS)

_msg: 
	@echo "Messages are made in usr/src/cmd/lp"

install:	$(ROOTLIBS) $(ROOTLINKS)

cstyle:
	cstyle $(SRCS)

lint:
	$(LINT.c) $(SRCS)

strip:

include		../../../../lib/Makefile.targ

include		../Makefile.msg
