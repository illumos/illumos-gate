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

PROG=	smbd
SRCS=				\
	smbd_door_ops.c		\
	smbd_doorsvc.c		\
	smbd_join.c		\
	smbd_logon.c		\
	smbd_main.c		\
	smbd_mlsvc_doorsvc.c	\
	smbd_net.c		\
	smbd_share_doorsvc.c

include ../../Makefile.cmd

MANIFEST  = server.xml

ROOTMANIFESTDIR	= $(ROOTSVCSMB)
$(ROOTMANIFEST):= FILEMODE = 0444

include ../Makefile.smbsrv.defs

LDLIBS += -lmlsvc -lmlrpc -lsmbrdr -lsmbns -lsmb -lbsm -lnsl -lumem

ROOTSMBDDIR = $(ROOTLIB)/smbsrv
ROOTSMBDFILE = $(PROG:%=$(ROOTSMBDDIR)/%)

FILEMODE = 0444
$(ROOTSMBDFILE):= FILEMODE = 0555

$(ROOTSMBDDIR)/%: %
	$(INS.file)

all:		$(PROG)

clean:
	$(RM) $(OBJS)

lint:		lint_SRCS

$(PROG):	$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

check:		$(CHKMANIFEST)

_msg:

include ../../Makefile.targ

install: all .WAIT $(ROOTETCDEFAULTFILES) $(ROOTMANIFEST) \
		$(ROOTSMBDFILE)
