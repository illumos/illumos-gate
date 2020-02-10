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
# Copyright 2016 Nexenta Systems, Inc.
#

include ../../Makefile.cmd

ETCSVC = $(ROOTETC)/svc
LIBSVCSEED = $(ROOT)/lib/svc/seed
INSTALLSEED = $(ROOT)/usr/sadm/install

#
# Because seed repository construction requires a functioning repository, a
# working svccfg(1) binary, and XML support, the following libraries must exist
# on the build system or in the proto area:  libscf, libuutil, and libxml2.
#

#
# We build and deliver 3 seed repositories:
#	global.db	-- for a standalone Solaris (global zone)
#	nonglobal.db	-- for a Solaris Zone
#	miniroot.db	-- for the install miniroot
# COMMON_DESCRIPTIONS contains manifests needed by all 3 repositories.
# GLOBAL_ZONE_DESCRIPTIONS/NONGLOBAL_ZONE_DESCRIPTIONS/MINIROOT_DESCRIPTIONS
# contain additional manifests needed.
#

#
# Manifests needed by all seed repositories. If you change this, you
# must test Solaris standalone, Solaris zone, and Install miniroot.
#
COMMON_DESCRIPTIONS = \
	../milestone/boot-archive.xml \
	../milestone/devices-local.xml \
	../milestone/global.xml \
	../milestone/identity.xml \
	../milestone/local-fs.xml \
	../milestone/manifest-import.xml \
	../milestone/minimal-fs.xml \
	../milestone/multi-user.xml \
	../milestone/name-services.xml \
	../milestone/network-initial.xml \
	../milestone/network-loopback.xml \
	../milestone/network-netcfg.xml \
	../milestone/network-physical.xml \
	../milestone/restarter.xml \
	../milestone/root-fs.xml \
	../milestone/single-user.xml \
	../milestone/usr-fs.xml \
	../../dlmgmtd/dlmgmt.xml \
	../../cmd-inet/lib/ipmgmtd/network-ipmgmt.xml \
	../../rpcbind/bind.xml

#
# Additional manifests for standalone Solaris
#
GLOBAL_ZONE_DESCRIPTIONS = \
	../milestone/console-login.xml \
	../milestone/multi-user-server.xml \
	../../cmd-inet/usr.lib/inetd/inetd-upgrade.xml \
	../../utmpd/utmp.xml

#
# Additional manifests for a Solaris zone
#
NONGLOBAL_ZONE_DESCRIPTIONS = \
	../milestone/console-login.xml \
	../milestone/multi-user-server.xml \
	../../utmpd/utmp.xml

#
# Additional manifests for the install miniroot.
#
MINIROOT_DESCRIPTIONS= \
	../milestone/sysconfig.xml \
	../../cmd-inet/usr.lib/inetd/inetd.xml \
	../../cmd-inet/usr.sbin/login.xml \
	../milestone/network-service.xml \
	../../cmd-inet/usr.sbin/telnet.xml \
	../../../lib/libresolv2/client.xml \
	../../ldapcachemgr/client.xml \
	../../ypcmd/client.xml \
	../../ypcmd/server.xml \
	../../keyserv/keyserv.xml \
	../../cmd-crypto/scripts/cryptosvc.xml \
	../../nscd/name-service-cache.xml \
	../../syslogd/system-log.xml

FILEMODE = 0600
SEEDFILEMODE = 0444		# seeds are not intended for editing, but may
				# be copied

CONFIGD = ../configd/svc.configd-native
SVCCFG = ../svccfg/svccfg-native

.KEEP_STATE:

all: global.db nonglobal.db miniroot.db

$(CONFIGD): FRC
	@cd ../configd; pwd; $(MAKE) $(MFLAGS) native

$(SVCCFG): FRC
	@cd ../svccfg; pwd; $(MAKE) $(MFLAGS) native

../milestone/console-login.xml:
	@cd ../milestone; pwd; $(MAKE) $(MFLAGS) console-login.xml

common.db: $(COMMON_DESCRIPTIONS) $(CONFIGD) $(SVCCFG)
	$(RM) -f common.db common.db-journal
	for m in $(COMMON_DESCRIPTIONS); do \
		echo $$m; \
		SVCCFG_DTD=../dtd/service_bundle.dtd.1 \
		SVCCFG_REPOSITORY=$(SRC)/cmd/svc/seed/common.db \
		SVCCFG_CONFIGD_PATH=$(CONFIGD) \
		$(SVCCFG) import $$m; \
	done

global.db: common.db $(GLOBAL_ZONE_DESCRIPTIONS) $(CONFIGD) $(SVCCFG)
	$(RM) -f global.db global.db-journal
	$(CP) common.db global.db
	for m in $(GLOBAL_ZONE_DESCRIPTIONS); do \
		echo $$m; \
		SVCCFG_DTD=../dtd/service_bundle.dtd.1 \
		SVCCFG_REPOSITORY=$(SRC)/cmd/svc/seed/global.db \
		SVCCFG_CONFIGD_PATH=$(CONFIGD) \
		$(SVCCFG) import $$m; \
	done

nonglobal.db: common.db $(NONGLOBAL_ZONE_DESCRIPTIONS) $(CONFIGD) $(SVCCFG)
	$(RM) -f nonglobal.db nonglobal.db-journal
	$(CP) common.db nonglobal.db
	for m in $(NONGLOBAL_ZONE_DESCRIPTIONS); do \
		echo $$m; \
		SVCCFG_DTD=../dtd/service_bundle.dtd.1 \
		SVCCFG_REPOSITORY=$(SRC)/cmd/svc/seed/nonglobal.db \
		SVCCFG_CONFIGD_PATH=$(CONFIGD) \
		$(SVCCFG) import $$m; \
	done

miniroot.db: common.db $(MINIROOT_DESCRIPTIONS) $(CONFIGD) $(SVCCFG)
	$(RM) -f miniroot.db miniroot.db-journal
	$(CP) common.db miniroot.db
	for m in $(MINIROOT_DESCRIPTIONS); do \
		echo $$m; \
		SVCCFG_DTD=../dtd/service_bundle.dtd.1 \
		SVCCFG_REPOSITORY=$(SRC)/cmd/svc/seed/miniroot.db \
		SVCCFG_CONFIGD_PATH=$(CONFIGD) \
		$(SVCCFG) import $$m; \
	done
	#
	# Make sure the miniroot's syslogd and rpcbind do not respond
	# to packets from outside the machine. Since we cannot set property
	# values by applying a profile yet, we need to set them explicitly
	# with svccfg commands.
	#
	SVCCFG_DTD=../dtd/service_bundle.dtd.1 \
	SVCCFG_REPOSITORY=$(SRC)/cmd/svc/seed/miniroot.db \
	SVCCFG_CONFIGD_PATH=$(CONFIGD) \
	$(SVCCFG) -s svc:/system/system-log \
	    setprop config/log_from_remote = false
	#
	SVCCFG_DTD=../dtd/service_bundle.dtd.1 \
	SVCCFG_REPOSITORY=$(SRC)/cmd/svc/seed/miniroot.db \
	SVCCFG_CONFIGD_PATH=$(CONFIGD) \
	$(SVCCFG) -s svc:/network/rpc/bind setprop config/local_only = true

install: install_global install_nonglobal install_miniroot

install_global: global.db
	$(RM) $(LIBSVCSEED)/global.db
	$(INS) -f $(LIBSVCSEED) -m $(SEEDFILEMODE) -s global.db

install_nonglobal: nonglobal.db
	$(RM) $(LIBSVCSEED)/nonglobal.db
	$(INS) -f $(LIBSVCSEED) -m $(SEEDFILEMODE) -s nonglobal.db

install_miniroot: $(INSTALLSEED) miniroot.db
	$(RM) $(INSTALLSEED)/miniroot.db
	$(INS) -f $(INSTALLSEED) -m $(SEEDFILEMODE) -s miniroot.db

$(INSTALLSEED):
	$(INS.dir)

clean lint:
	$(RM) common.db

clobber:
	$(RM) common.db global.db nonglobal.db miniroot.db

FRC:
