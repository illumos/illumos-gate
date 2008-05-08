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

PROG	= in.mpathd
OBJS	= mpd_tables.o mpd_main.o mpd_probe.o
SRCS	= $(OBJS:%.o=%.c)

DEFAULTFILES = mpathd.dfl

include ../../../Makefile.cmd

POFILE	= $(PROG).po
POFILES = $(SRCS:%.c=%.po)

C99MODE= $(C99_ENABLE)

#
# We need access to the ancillary data features which are only available
# via the SUS standards.  Further, C99 support requires SUSv3 or higher.
#
CPPFLAGS += -D_XOPEN_SOURCE=600 -D__EXTENSIONS__
LDLIBS	+= -lsocket -lnsl -lsysevent -lnvpair -lipmp -lc

LINTFLAGS += -erroff=E_FUNC_DECL_VAR_ARG2 -erroff=E_INCONS_VAL_TYPE_DECL2 \
	    -erroff=E_FUNC_USED_VAR_ARG2 -erroff=E_INCONS_ARG_DECL2 \
	    -erroff=E_NAME_USED_NOT_DEF2 -erroff=E_INCONS_ARG_USED2 \
	    -errtags=yes

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

include ../Makefile.lib

$(ROOTSBINPROG):
		$(RM) $@; $(SYMLINK) ../usr/lib/inet/$(PROG) $@

install:	all $(ROOTLIBINETPROG) $(ROOTSBINPROG) $(ROOTETCDEFAULTFILES)

clean:
		$(RM) $(OBJS)

lint:		lint_SRCS

$(POFILE): 	$(POFILES)
		$(RM) $@
		$(CAT) $(POFILES) > $@

include ../../../Makefile.targ
