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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Makefile definitions for Sun Fire 15000 Key Management Daemon (sckmd)
#

PROG=		sckmd

PLATFORM=	SUNW,Sun-Fire-15000

CLASS=		32

SRCS=		$(PROG:%=%.c)

OBJS=		$(SRCS:%.c=%.o)

LINT_SRCS=	$(SRCS)
LINT_FILES=	$(LINT_SRCS:%.c=%.ln)


include ../../../Makefile.cmd
include ../../../../Makefile.psm


OWNER=		root
GROUP=		sys

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
# Definitions for building init scripts
#
SHPROG =		sckm
SHPROG_STARTPRIO =	70
SHPROG_KILLPRIO =	42

ROOTINIT_D =		$(ROOTETC)/init.d
ROOTRC0_D =		$(ROOTETC)/rc0.d
ROOTRCS_D =		$(ROOTETC)/rcS.d
ROOTRC1_D =		$(ROOTETC)/rc1.d
ROOTRC2_D =		$(ROOTETC)/rc2.d

ROOTINIT_D_SHPROG =	$(ROOTINIT_D)/$(SHPROG)
ROOTRCLINKS =		$(ROOTRC0_D)/K$(SHPROG_KILLPRIO)$(SHPROG) \
			$(ROOTRCS_D)/K$(SHPROG_KILLPRIO)$(SHPROG) \
			$(ROOTRC1_D)/K$(SHPROG_KILLPRIO)$(SHPROG) \
			$(ROOTRC2_D)/S$(SHPROG_STARTPRIO)$(SHPROG)

$(ROOTINIT_D_SHPROG) $(ROOTRCLINKS) :=	FILEMODE =	744


#
# Build rules
#
.KEEP_STATE:


all: $(PROG) $(SHPROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(USRPSMPROG) $(ROOTINIT_D_SHPROG) $(ROOTRCLINKS)

lint:
	$(LINT) $(LINT_FLAGS) $(CPPFLAGS) $(LINT_SRCS)

clean:
	$(RM) $(PROG) $(SHPROG) $(OBJS) *.po $(LINT_FILES) core


#
# Build rules for init scripts
#
$(ROOTINIT_D)/%: %
	$(INS.file)

$(ROOTRCLINKS): $(ROOTINIT_D_SHPROG)
	$(RM) $@; $(LN) $(ROOTINIT_D_SHPROG) $@


include ../../../Makefile.targ
include ../../../../Makefile.psm.targ
