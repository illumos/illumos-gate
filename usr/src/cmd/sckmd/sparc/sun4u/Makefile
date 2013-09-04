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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Makefile definitions for Sun Fire 15000 Key Management Daemon (sckmd)
#

PROG=		sckmd

PLATFORM=	sun4u

CLASS=		32

SRCS=		$(PROG:%=%.c)

OBJS=		$(SRCS:%.c=%.o)

LINT_SRCS=	$(SRCS)
LINT_FILES=	$(LINT_SRCS:%.c=%.ln)


include ../../../Makefile.cmd
include ../../../../Makefile.psm


USRPSMPROG=	$(USR_PSM_LIB_DIR)/$(PROG)
$(USRPSMPROG) :=	FILEMODE =	0755


#
# FLAGS:
#
CPPFLAGS= 	-I$(USR_PSM_INCL_DIR) -I$(SRC)/uts/sun4u/starcat $(CPPFLAGS.master)

LINT_FLAGS=	-c -Nlevel=4 -Ncheck


#
# LIBRARIES:
#
LDLIBS +=	-lsocket -lipsecutil

#
# Build rules
#
.KEEP_STATE:


all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(USRPSMPROG)

lint:
	$(LINT) $(LINT_FLAGS) $(CPPFLAGS) $(LINT_SRCS)

clean:
	$(RM) $(PROG) $(OBJS) *.po $(LINT_FILES)


include ../../../Makefile.targ
include ../../../../Makefile.psm.targ
