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
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../../Makefile.cmd

FILEMODE = 0444

BUILTXML= \
	console-login.xml

FSSVCS= \
	local-fs.xml \
	minimal-fs.xml \
	root-fs.xml \
	usr-fs.xml

FSMANIFESTS= $(FSSVCS:%=$(ROOTSVCSYSTEMFILESYSTEM)/%)

NETSVCS= \
	network-initial.xml \
	network-install.xml \
	network-iptun.xml \
	network-ipqos.xml \
	network-location.xml \
	network-loopback.xml \
	network-netcfg.xml \
	network-netmask.xml \
	network-netcfg.xml \
	network-physical.xml \
	network-routing-setup.xml \
	network-service.xml

NETMANIFESTS= $(NETSVCS:%=$(ROOTSVCNETWORK)/%)

MAINMILESTONES= \
	multi-user-server.xml \
	multi-user.xml \
	name-services.xml \
	network.xml \
	single-user.xml \
	sysconfig.xml

MAINMANIFESTS= $(MAINMILESTONES:%=$(ROOTSVCMILESTONE)/%)

SYSDEVSVCS= \
	devices-local.xml \
	devices-audio.xml

SYSDEVMANIFESTS= $(SYSDEVSVCS:%=$(ROOTSVCSYSTEMDEVICE)/%)

SYSTEMSVCS= \
	boot-archive.xml \
	console-login.xml \
	early-manifest-import.xml \
	identity.xml \
	manifest-import.xml \
	process-security.xml \
	rmtmpfiles.xml	\
	vtdaemon.xml

SYSTEMMANIFESTS = $(SYSTEMSVCS:%=$(ROOTSVCSYSTEM)/%)

SYSTEMSVCSVCS= \
	restarter.xml \
	global.xml

SYSTEMSVCMANIFESTS= $(SYSTEMSVCSVCS:%=$(ROOTSVCSYSTEM)/svc/%)

MISCFILES= \
	README.share

SYSTEMMISCFILES = $(MISCFILES:%.share=$(ROOT)/lib/svc/share/%)

#
# MANIFEST is used solely in the construction of the check target.
#
MANIFEST= $(FSSVCS) $(NETSVCS) $(MAINMILESTONES) $(SYSTEMSVCS) \
	$(SYSDEVSVCS) $(SYSTEMSVCSVCS)

SVCMETHOD=\
	boot-archive \
	console-login \
	devices-audio \
	devices-local \
	fs-local \
	fs-minimal \
	fs-root \
	fs-usr \
	identity-domain \
	identity-node \
	manifest-import \
	net-loc \
	net-loopback \
	net-init \
	net-install \
	net-iptun \
	net-ipqos \
	net-netmask \
	net-nwam \
	net-physical \
	net-routing-setup \
	net-svc \
	rmtmpfiles \
	vtdaemon

$(ROOTSVCMETHOD) := FILEMODE = 0555

all: $(BUILTXML)

install: $(FSMANIFESTS) $(MAINMANIFESTS) $(NETMANIFESTS) $(SYSTEMMANIFESTS) \
	$(ROOTSVCMETHOD) $(SYSDEVMANIFESTS) $(SYSTEMSVCMANIFESTS) \
	$(SYSTEMMISCFILES)

check:	$(CHKMANIFEST)

console-login.xml: make-console-login-xml
	$(SH) ./make-console-login-xml

clobber: clean
	-$(RM) $(BUILTXML)

$(ROOTSVCMILESTONE)/%: %
	$(INS.file)

$(ROOTSVCNETWORK)/%: %
	$(INS.file)

$(ROOTSVCSYSTEM)/%: %
	$(INS.file)

$(ROOTSVCSYSTEMDEVICE)/%: %
	$(INS.file)

$(ROOTSVCSYSTEMFILESYSTEM)/%: %
	$(INS.file)

$(ROOTSVCSYSTEM)/svc/%: %
	$(INS.file)

$(ROOT)/lib/svc/share/%: %.share
	$(INS.rename)

clean lint _msg:
