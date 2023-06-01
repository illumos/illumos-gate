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
# Copyright 2021 Tintri by DDN, Inc. All rights reserved.
#

PROG		= in.mpathd
ROOTFS_PROG	= $(PROG)
OBJS		= mpd_tables.o mpd_main.o mpd_probe.o
DEFAULTFILES	= mpathd.dfl
SVCMETHOD	= net-ipmp
MANIFEST	= network-ipmp.xml

include ../../../Makefile.cmd

ROOTCMDDIR	= $(ROOT)/lib/inet
ROOTMANIFESTDIR	= $(ROOTSVCNETWORK)

POFILE		= $(PROG).po
POFILES		= $(OBJS:%.o=%.po)

CSTD		= $(CSTD_GNU99)

#
# We need access to the ancillary data features which are only available
# via the SUS standards.  Further, C99 support requires SUSv3 or higher.
#
CPPFLAGS += -D_XOPEN_SOURCE=600 -D__EXTENSIONS__
LDLIBS	+= -lsocket -lnsl -lsysevent -lnvpair -lipmp -linetutil -ldlpi

CERRWARN += $(CNOWARN_UNINIT)

#
# Instrument in.mpathd with CTF data to ease debugging.
#
CTFCONVERT_HOOK = && $(CTFCONVERT_O)
CTFMERGE_HOOK = && $(CTFMERGE) -L VERSION -o $@ $(OBJS)
$(OBJS) := CFLAGS += $(CTF_FLAGS)

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS) $(CTFMERGE_HOOK)
		$(POST_PROCESS)

check:		$(CHKMANIFEST)

install:	all $(ROOTCMD) $(ROOTMANIFEST) $(ROOTSVCMETHOD) \
		$(ROOTETCDEFAULTFILES)

clean:
		$(RM) $(OBJS)

$(POFILE):	$(POFILES)
		$(RM) $@
		$(CAT) $(POFILES) > $@

include ../../../Makefile.targ
