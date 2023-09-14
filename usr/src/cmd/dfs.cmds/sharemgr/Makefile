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

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../../Makefile.cmd
include ../../Makefile.ctf

MANIFEST=	group.xml
PROG=		sharemgr

LINKS=		share unshare
ROOTLINKS=	$(LINKS:%=$(ROOTUSRSBIN)/%)
$(ROOTLINKS)	:= INSLINKTARGET = $(ROOTUSRSBINPROG)
ROOTMANIFESTDIR	= $(ROOTSVCNETWORKSHARES)
$(ROOTMANIFEST)	:= FILEMODE= 444

OBJS	= sharemgr_main.o commands.o shareutil.o

CPPFLAGS += -I../../../lib/libfsmgt/common
CPPFLAGS += -I$(ADJUNCT_PROTO)/usr/include/libxml2
LDLIBS += -lshare -lscf -lsecdb -lumem -lxml2
NATIVE_LIBS += libxml2.so

POFILES = $(OBJS:.o=.po)
POFILE  = sharemgr.po

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

$(ROOTLINKS): $(ROOTUSRSBINPROG)
	$(INS.link)

install: all $(ROOTUSRSBINPROG) $(ROOTMANIFEST) $(ROOTLINKS)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

include ../../Makefile.targ

$(POFILE):      $(POFILES)
	$(RM) $@; cat $(POFILES) > $@
