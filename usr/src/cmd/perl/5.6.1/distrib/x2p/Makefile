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
# Copyright (c) 2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

.KEEP_STATE:

include ../../../../Makefile.cmd
include ../../Makefile.perlcfg
 
# Add in the perl-specific flags (including largefile flags).
CPPFLAGS += -DPERL_FOR_X2P $(PERL_LFFLAGS)

# From the standard perl x2p Makefile.
PL_SRCS = find2perl.PL s2p.PL
PL_TARGS = $(PL_SRCS:%.PL=%)
POD_SRCS = a2p.pod
POD_TARGS = $(POD_SRCS:%=../pod/%)

# a2p components.
HDRS = a2p.h EXTERN.h hash.h INTERN.h str.h util.h ../config.h ../handy.h
SRCS = hash.c str.c util.c walk.c a2p.c
OBJS = $(SRCS:%.c=%.o)
TARGS = a2p $(PL_TARGS) $(POD_TARGS)

CLOBBERFILES= $(TARGS)
CLEANFILES= $(OBJS)

all: $(TARGS)
.PARALLEL: $(OBJS) $(TARGS)

a2p: $(OBJS)
	$(LINK.c) -o a2p $(OBJS) $(LDLIBS) $(PERL_LDLIBS)

# We don't want to regenerate a2p.c, but it might appear out-of-date
# after a patch is applied or a new distribution is made.
a2p.c: a2p.y
	@ $(TOUCH) $@

a2p.o: a2p.c a2py.c $(HDRS)

# Use miniperl to build scripts.
$(PL_TARGS): ../lib/Config.pm
	../miniperl -I../lib $@.PL

../pod/%.pod: %.pod ../lib/Config.pm
	$(CP) -f $< $@

clean:
	$(RM) $(CLEANFILES)

include ../../../../Makefile.targ
