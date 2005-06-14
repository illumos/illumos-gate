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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

include ../../Makefile.cmd

ETCSVC = $(ROOTETC)/svc
LIBSVCSEED = $(ROOT)/lib/svc/seed

#
# Because seed repository construction requires a functioning repository, a
# working svccfg(1) binary, and XML support, the following libraries must exist
# on the build system or in the proto area:  libscf, libuutil, and libxml2.
#

#
# GLOBAL_ZONE_DESCRIPTIONS and NONGLOBAL_ZONE_DESCRIPTIONS contain the
# services used to define a 'seed repository' for a standalone Solaris
# instance or for a zone, respectively.  A service needed for either one of
# these seeds must be added to the appropriate macro.  The definition of a seed
# repository is a self-consistent set of services that can boot.
#
GLOBAL_ZONE_DESCRIPTIONS = \
	../milestone/boot-archive.xml \
	../milestone/console-login.xml \
	../milestone/datalink.xml \
	../milestone/datalink-init.xml \
	../milestone/devices-local.xml \
	../milestone/identity.xml \
	../milestone/local-fs.xml \
	../milestone/manifest-import.xml \
	../milestone/minimal-fs.xml \
	../milestone/multi-user-server.xml \
	../milestone/multi-user.xml \
	../milestone/name-services.xml \
	../milestone/aggregation.xml \
	../milestone/network-initial.xml \
	../milestone/network-loopback.xml \
	../milestone/network-physical.xml \
	../milestone/restarter.xml \
	../milestone/root-fs.xml \
	../milestone/single-user.xml \
	../milestone/usr-fs.xml \
	../../rpcbind/bind.xml \
	../../cmd-inet/usr.lib/inetd/inetd-upgrade.xml \
	../../utmpd/utmp.xml \
	../../lvm/util/metainit.xml \
	../../ipf/svc/pfil.xml

NONGLOBAL_ZONE_DESCRIPTIONS = \
	../milestone/boot-archive.xml \
	../milestone/console-login.xml \
	../milestone/datalink.xml \
	../milestone/devices-local.xml \
	../milestone/identity.xml \
	../milestone/local-fs.xml \
	../milestone/manifest-import.xml \
	../milestone/minimal-fs.xml \
	../milestone/multi-user-server.xml \
	../milestone/multi-user.xml \
	../milestone/name-services.xml \
	../milestone/aggregation.xml \
	../milestone/network-initial.xml \
	../milestone/network-loopback.xml \
	../milestone/network-physical.xml \
	../milestone/restarter.xml \
	../milestone/root-fs.xml \
	../milestone/single-user.xml \
	../milestone/usr-fs.xml \
	../../rpcbind/bind.xml \
	../../utmpd/utmp.xml

OWNER = root
GROUP = sys
FILEMODE = 0600
SEEDFILEMODE = 0444		# seeds are not intended for editing, but may
				# be copied

CONFIGD = ../configd/svc.configd-native
SVCCFG = ../svccfg/svccfg-native

.KEEP_STATE:

all: global.db nonglobal.db

$(CONFIGD): FRC
	@cd ../configd; pwd; $(MAKE) $(MFLAGS) native

$(SVCCFG): FRC
	@cd ../svccfg; pwd; $(MAKE) $(MFLAGS) native

../milestone/console-login.xml:
	@cd ../milestone; pwd; $(MAKE) $(MFLAGS) console-login.xml

global.db: $(GLOBAL_ZONE_DESCRIPTIONS) $(CONFIGD) $(SVCCFG)
	$(RM) -f global.db global.db-journal
	for m in $(GLOBAL_ZONE_DESCRIPTIONS); do \
		echo $$m; \
		SVCCFG_DTD=../dtd/service_bundle.dtd.1 \
		SVCCFG_REPOSITORY=$(SRC)/cmd/svc/seed/global.db \
		SVCCFG_CONFIGD_PATH=$(CONFIGD) \
		$(SVCCFG) import $$m; \
	done

nonglobal.db: $(NONGLOBAL_ZONE_DESCRIPTIONS) $(CONFIGD) $(SVCCFG)
	$(RM) -f nonglobal.db global.db-journal
	for m in $(NONGLOBAL_ZONE_DESCRIPTIONS); do \
		echo $$m; \
		SVCCFG_DTD=../dtd/service_bundle.dtd.1 \
		SVCCFG_REPOSITORY=$(SRC)/cmd/svc/seed/nonglobal.db \
		SVCCFG_CONFIGD_PATH=$(CONFIGD) \
		$(SVCCFG) import $$m; \
	done

install: install_global install_nonglobal

install_global: global.db
	$(RM) $(LIBSVCSEED)/global.db
	$(INS) -f $(LIBSVCSEED) -m $(SEEDFILEMODE) -s global.db

install_nonglobal: nonglobal.db
	$(RM) $(LIBSVCSEED)/nonglobal.db
	$(INS) -f $(LIBSVCSEED) -m $(SEEDFILEMODE) -s nonglobal.db

clean lint:

clobber:
	$(RM) global.db nonglobal.db

FRC:
