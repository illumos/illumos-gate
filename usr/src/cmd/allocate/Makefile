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
# Copyright 1989, 1998-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include		../Makefile.cmd

ROOTSEC =	$(ROOTETC)/security
ROOTSECDEV =	$(ROOTSEC)/dev
ROOTSECLIB =	$(ROOTSEC)/lib
ROOTDIRS =	$(ROOTSECDEV) $(ROOTSECLIB)

PROG1 =		allocate
PROG2 =		mkdevmaps mkdevalloc
PROG3 =		audio_clean
PROG =		$(PROG1) $(PROG2) $(PROG3)
DEFILE =	deallocate
LISTFILE =	list_devices
RTLCKS =	audio fd0 sr0 st0 st1
SCRIPTS =	st_clean fd_clean sr_clean
ALLSCRIPTS =	allscripts.sh

POFILE=		allocate_all.po
POFILES=	$(OBJS:%.o=%.po) $(ALLSCRIPTS:%.sh=%.po)

# make DFLAGS=-DDEBUG

DFLAGS=
CPPFLAGS +=	$(DFLAGS)

ROOTPROG =	$(PROG1:%=$(ROOTUSRSBIN)/%) $(PROG2:%=$(ROOTUSRSBIN)/%) \
		$(PROG3:%=$(ROOTSECLIB)/%)
ROOTLOCKS=	$(RTLCKS:%=$(ROOTSECDEV)/%)
ROOTSCRIPTS=	$(SCRIPTS:%=$(ROOTSECLIB)/%)

CLOBBERFILES += $(SCRIPTS)

allocate :=	POBJS = allocate.o  allocate3.o
mkdevmaps :=	POBJS = mkdevmaps.o
mkdevalloc :=	POBJS = mkdevalloc.o
audio_clean :=	POBJS = audio_clean.o

OBJS =		allocate.o allocate3.o audio_clean.o mkdevmaps.o mkdevalloc.o
SRCS =		$(OBJS:%.o=%.c)

FILEMODE=       0755
DIRMODE=        0755
OWNER=          root
GROUP=          sys

$(ROOTUSRSBIN)/% :=     OWNER = root 
$(ROOTUSRSBIN)/% :=     GROUP = bin 

$(ROOTUSRSBIN)/allocate := 	FILEMODE = 04755
$(ROOTUSRSBIN)/deallocate :=	FILEMODE = 04755
$(ROOTUSRSBIN)/list_devices :=	FILEMODE = 04755

$(ROOTSECDEV)/% :=		FILEMODE = 0400
$(ROOTSECDEV)/% :=              OWNER = root
$(ROOTSECDEV)/% :=              GROUP = bin

$(ROOTSECLIB)/% :=		FILEMODE = 0751

allocate :=	LDLIBS += -lbsm -lsecdb

.KEEP_STATE:

all :		$(PROG) $(RTLCKS) $(SCRIPTS)

install :	all $(ROOTDIRS) $(ROOTPROG) $(ROOTLOCKS) $(ROOTSCRIPTS)
		$(RM) $(ROOTUSRSBIN)/$(DEFILE)
		$(LN) $(ROOTUSRSBIN)/$(PROG1) $(ROOTUSRSBIN)/$(DEFILE)
		$(RM) $(ROOTUSRSBIN)/$(LISTFILE)
		$(LN) $(ROOTUSRSBIN)/$(PROG1) $(ROOTUSRSBIN)/$(LISTFILE)

$(PROG) :	$$(POBJS)
		$(LINK.c) $(POBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(RTLCKS):
		$(TOUCH) $@

$(ROOTDIRS):
		$(INS.dir)

$(ROOTSECDEV)/%: %
		$(INS.file)

$(ROOTSECLIB)/%: %
		$(INS.file)

$(POFILE):      $(POFILES)
		$(RM) $@; $(CAT) $(POFILES) > $@; $(RM)  $(POFILES)

#
# Concatenate all the scripts into one before we build the catalogue.
# Done to shrink the catalogue since some messages are shared between
# the various scripts.
#
$(ALLSCRIPTS):	$(SCRIPTS:%=%.sh)
		$(CAT) $(SCRIPTS:%=%.sh) > $@

clean :
		$(RM) $(OBJS) $(RTLCKS) $(ALLSCRIPTS)

lint :		lint_SRCS

strip :
		$(STRIP) $(PROG)

include		../Makefile.targ
