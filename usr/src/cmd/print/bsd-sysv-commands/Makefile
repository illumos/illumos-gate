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
# Copyright (c) 2018, Joyent, Inc.

include		../Makefile.sp

UCBPROGS =	lpr lpq lprm lpc
BINPROGS =	lp lpstat cancel enable disable $(UCBPROGS)
SBINPROGS =	accept reject lpmove

LIBPRINTPROGS =	in.lpd

LIBLPPROGS = $(BINPROGS) $(SBINPROGS)


OBJS =	$(BINPROGS:=.o) $(SBINPROGS:=.o) $(LIBPRINTPROGS:=.o) common.o

ROOTLIBLPBIN=$(ROOTLIBLP)/bin

ROOTBINPROGS =		$(BINPROGS:%=$(ROOTBIN)/%)
ROOTUSRSBINPROGS =	$(SBINPROGS:%=$(ROOTUSRSBIN)/%)
ROOTLIBPRINTPROGS =	$(LIBPRINTPROGS:%=$(ROOTLIBPRINT)/%)
ROOTLIBLPPROGS =	$(LIBLPPROGS:%=$(ROOTLIBLPBIN)/%)


FILEMODE =	0555

include ../../Makefile.cmd

MANIFEST=	rfc1179.xml
ROOTMANIFESTDIR=	$(ROOTSVCAPPLICATIONPRINT)
$(ROOTMANIFEST)		:= FILEMODE= 444

LPLIB	=	$(SRC)/cmd/lp/lib
LIBLP	=	$(LPLIB)/lp/liblp.a
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I.
CPPFLAGS +=	-I../../../lib/print/libpapi-common/common
CPPFLAGS +=	-I$(ROOT)/usr/include
CPPFLAGS +=	-I../../lp/include
LDLIBS +=	$(LIBLP) -lpapi -lc
in.lpd:=	CFLAGS +=	-DSOLARIS_PRIVATE_POST_0_9
in.lpd:=	LDLIBS +=	-lnsl -lsocket

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized

# not linted
SMATCH=off

all:	$(BINPROGS) $(SBINPROGS)

#	each program needs common.o as well
$(BINPROGS) $(SBINPROGS) $(LIBPRINTPROGS):	$(BINPROGS:%=%.c) $(SBINPROGS:%=%.c)  $(LIBPRINTPROGS:%=%.c) common.o
	$(LINK.c) -o $@ $@.c common.o $(LDLIBS)
	$(POST_PROCESS)

#	ucb links (lptest is handled in usr/src/cmd/lp/cmd/Makefile)
ROOTUSRUCB =		$(ROOT)/usr/ucb
ROOTUCBSYMLINKS =	$(UCBPROGS:%=$(ROOTUSRUCB)/%)
$(ROOTUSRUCB)/%:	$(ROOTUSRUCB) %

$(ROOTLIBLPBIN)/%:	%
	$(INS.file)

$(ROOTUCBSYMLINKS):	
	$(RM) $@; $(SYMLINK) ../bin/$(@F) $@

#	usr/lib links
ROOTUSRLIBSYMLINKS =	$(SBINPROGS:%=$(ROOTLIB)/%)
$(ROOTLIB)/%:	$(ROOTLIB) %

$(ROOTUSRLIBSYMLINKS):	
	$(RM) $@; $(SYMLINK) ../sbin/$(@F) $@

.KEEP_STATE:

install:	$(ROOTLIBLPPROGS) \
		$(ROOTLIBPRINT) $(ROOTLIBPRINTPROGS) $(ROOTMANIFEST) \
		$(ROOTUCBSYMLINKS) $(ROOTUSRLIBSYMLINKS)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS) 

CLOBBERFILES += $(BINPROGS) $(SBINPROGS) $(LIBPRINTPROGS)

lint:

include ../../Makefile.targ
