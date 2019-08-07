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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#


SVCMETHOD=	svc-legacy-routing svc-forwarding
MANIFEST=	legacy-routing.xml forwarding.xml

PROG=		routeadm
ROOTFS_PROG=	$(PROG)

include ../../../Makefile.cmd

#
# We cannot use the usual manifest rules here since we deliver
# manifests to two different locations, /lib/svc/manifest/network/forwarding.xml
# and /lib/svc/manifest/network/routing/legacy-routing.xml
#

ROOTSVCMANIFESTDIR=	$(ROOTSVCNETWORK) $(ROOTSVCNETWORKROUTING)
ROOTSVCMANIFESTS=	$(ROOTSVCNETWORKROUTING)/legacy-routing.xml \
			$(ROOTSVCNETWORK)/forwarding.xml

include ../../Makefile.cmd-inet

$(ROOTSVCMANIFESTS)	:=	FILEMODE= 444

ROOTUSRSBINLINKS=	$(PROG:%=$(ROOTUSRSBIN)/%)

CPPFLAGS +=	-I../../../../common/svc -I$(CMDINETCOMMONDIR)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
$(NOT_RELEASE_BUILD)CPPFLAGS +=	-DDEBUG

LDLIBS +=		-lscf -luutil -lsocket

ROOTSBINPROG=		$(ROOTFS_PROG:%=$(ROOTSBIN)/%)

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTSBINPROG) $(ROOTUSRSBINLINKS) $(ROOTSVCMANIFESTS) \
	$(ROOTSVCMETHOD)

$(ROOTUSRSBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(@F) $@

check: 	$(CHKMANIFEST)

clean:

lint: lint_PROG

$(ROOTSVCMANIFESTS): $(ROOTSVCMANIFESTDIR)

$(ROOTSVCMANIFESTDIR):
	$(INS.dir)

$(ROOTSVCNETWORK)/%: %
	$(INS.file)

$(ROOTSVCNETWORKROUTING)/%: %
	$(INS.file)

include ../../../Makefile.targ
