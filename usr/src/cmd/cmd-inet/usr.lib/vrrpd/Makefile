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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

PROG=		vrrpd
OBJS=		vrrpd.o
SRCS=		$(OBJS:.o=.c)
SVCMETHOD=	svc-vrrp
MANIFEST=	vrrp.xml
CFGFILES=	vrrp.conf

include ../../../Makefile.cmd

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)

$(ROOTETC)/inet/$(CFGFILES):= FILEMODE= 644 
$(ROOTETC)/inet/$(CFGFILES):= OWNER= root 
$(ROOTETC)/inet/$(CFGFILES):= GROUP= sys 

CSTD=		$(CSTD_GNU99)

#
# We need access to the ancillary data features which are only available
# via the SUS standards.  Further, C99 support requires SUSv3 or higher.
#
CPPFLAGS += -D_XOPEN_SOURCE=600 -D__EXTENSIONS__
LDLIBS += -lvrrpadm -lsocket -lnsl -ldladm -linetutil -lipadm -lsysevent -lnvpair -lsecdb
LINTFLAGS += -erroff=E_INCONS_ARG_DECL2  -erroff=E_INCONS_ARG_USED2

CERRWARN += -_gcc=-Wno-uninitialized

#
# Instrument vrrpd with CTF data to ease debugging.
#
CTFCONVERT_HOOK = && $(CTFCONVERT_O)
CTFMERGE_HOOK = && $(CTFMERGE) -L VERSION -o $@ $(OBJS)
$(OBJS) := CFLAGS += $(CTF_FLAGS)

# for messaging catalog. No messages are present in CMN_DIR sources.
POFILES = $(LOCAL_OBJS:%.o=%.po)
XGETFLAGS += -a -x vrrpd.xcl

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

include ../Makefile.lib

install: all $(ROOTLIBINETPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD) \
	$(ROOTETC)/inet/$(CFGFILES)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../../../Makefile.targ
