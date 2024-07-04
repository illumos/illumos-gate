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
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
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

MFST_ROOT=lib/svc/manifest
MFST_TYPE= \
	system \
	system/device \
	system/filesystem \
	system/svc \
	milestone \
	network \
	network/dns \
	network/ldap \
	network/nis \
	network/rpc

MFST_DIRS = $(MFST_TYPE:%=$(MFST_ROOT)/%)

#
# We build and deliver 3 seed repositories:
#	global.db	-- for a standalone system (global zone)
#	nonglobal.db	-- for a non-global zone
#	miniroot.db	-- for the install miniroot
#
# COMMON_MANIFESTS contains manifests needed by all 3 repositories.
# {GLOBAL_ZONE,NONGLOBAL_ZONE,MINIROOT}_MANIFESTS
#   contain additional manifests needed.
#

#
# Manifests needed by all seed repositories.
#
COMMON_MANIFESTS = \
	milestone/multi-user.xml \
	milestone/name-services.xml \
	milestone/single-user.xml \
	network/dlmgmt.xml \
	network/network-initial.xml \
	network/network-ipmgmt.xml \
	network/network-loopback.xml \
	network/network-netcfg.xml \
	network/network-physical.xml \
	network/rpc/bind.xml \
	system/boot-archive.xml \
	system/device/devices-local.xml \
	system/filesystem/local-fs.xml \
	system/filesystem/minimal-fs.xml \
	system/filesystem/root-fs.xml \
	system/filesystem/usr-fs.xml \
	system/identity.xml \
	system/manifest-import.xml \
	system/svc/global.xml \
	system/svc/restarter.xml

#
# Additional manifests for a standalone system (global zone)
#
GLOBAL_ZONE_MANIFESTS = \
	milestone/multi-user-server.xml \
	network/inetd-upgrade.xml \
	system/console-login.xml \
	system/utmp.xml

#
# Additional manifests for a non-global zone
#
NONGLOBAL_ZONE_MANIFESTS = \
	milestone/multi-user-server.xml \
	system/console-login.xml \
	system/utmp.xml

#
# Additional manifests for the install miniroot.
#
MINIROOT_MANIFESTS= \
	milestone/sysconfig.xml \
	network/dns/client.xml \
	network/inetd.xml \
	network/ldap/client.xml \
	network/login.xml \
	network/network-service.xml \
	network/nis/client.xml \
	network/nis/server.xml \
	network/rpc/keyserv.xml \
	network/telnet.xml \
	system/cryptosvc.xml \
	system/name-service-cache.xml \
	system/system-log.xml


COMMON_DESCRIPTIONS=$(COMMON_MANIFESTS:%=$(MFST_ROOT)/%)
GLOBAL_ZONE_DESCRIPTIONS=$(GLOBAL_ZONE_MANIFESTS:%=$(MFST_ROOT)/%)
NONGLOBAL_ZONE_DESCRIPTIONS=$(NONGLOBAL_ZONE_MANIFESTS:%=$(MFST_ROOT)/%)
MINIROOT_DESCRIPTIONS=$(MINIROOT_MANIFESTS:%=$(MFST_ROOT)/%)

FILEMODE = 0600
# seeds are not intended for editing, but may be copied
SEEDFILEMODE = 0444

.KEEP_STATE:

all: global.db nonglobal.db miniroot.db

../milestone/console-login.xml:
	@cd ../milestone; pwd; $(MAKE) console-login.xml

CONFIGD_ENV = \
	SVCCFG_DTD=../dtd/service_bundle.dtd.1 \
	PKG_INSTALL_ROOT=$(SRC)/cmd/svc/seed \
	SVCCFG_REPOSITORY=$(SRC)/cmd/svc/seed/$@ \
	SVCCFG_CONFIGD_PATH=$(SVCCONFIGD)

IMPORT.mfst = $(CONFIGD_ENV) $(SVCCFG) import

common.db: $(MFST_DIRS) $(COMMON_DESCRIPTIONS)
	$(RM) -f $@ $@-journal
	$(IMPORT.mfst) $(COMMON_DESCRIPTIONS)

global.db: common.db $(GLOBAL_ZONE_DESCRIPTIONS)
	$(RM) -f $@ $@-journal
	$(CP) common.db $@
	$(IMPORT.mfst) $(GLOBAL_ZONE_DESCRIPTIONS)

nonglobal.db: common.db $(NONGLOBAL_ZONE_DESCRIPTIONS)
	$(RM) -f $@ $@-journal
	$(CP) common.db $@
	$(IMPORT.mfst) $(NONGLOBAL_ZONE_DESCRIPTIONS)

miniroot.db: common.db $(MINIROOT_DESCRIPTIONS)
	$(RM) -f $@ $@-journal
	$(CP) common.db $@
	$(IMPORT.mfst) $(MINIROOT_DESCRIPTIONS)
	#
	# Make sure the miniroot's syslogd and rpcbind do not respond
	# to packets from outside the machine. Since we cannot set property
	# values by applying a profile yet, we need to set them explicitly
	# with svccfg commands.
	#
	$(CONFIGD_ENV) $(SVCCFG) -s svc:/system/system-log \
	    setprop config/log_from_remote = false
	$(CONFIGD_ENV) $(SVCCFG) -s svc:/network/rpc/bind \
	    setprop config/local_only = true

.PARALLEL: global.db nonglobal.db miniroot.db

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

clean:
	$(RM) common.db
	$(RM) $(COMMON_DESCRIPTIONS) $(GLOBAL_ZONE_DESCRIPTIONS)
	$(RM) $(NON_GLOBAL_ZONE_DESCRIPTIONS) $(MINIROOT_DESCRIPTIONS)

clobber:
	$(RM) common.db global.db nonglobal.db miniroot.db
	$(RM) -r lib/

$(MFST_DIRS): FRC
	$(INS.dir)

$(MFST_ROOT)/milestone/%: ../milestone/%
	$(INS.file)

$(MFST_ROOT)/network/%: ../../cmd-inet/lib/ipmgmtd/%
	$(INS.file)

$(MFST_ROOT)/network/%: ../../cmd-inet/usr.lib/inetd/%
	$(INS.file)

$(MFST_ROOT)/network/%: ../../cmd-inet/usr.sbin/%
	$(INS.file)

$(MFST_ROOT)/network/%: ../../dlmgmtd/%
	$(INS.file)

$(MFST_ROOT)/network/%: ../milestone/%
	$(INS.file)

$(MFST_ROOT)/network/dns/%: ../../../lib/libresolv2/%
	$(INS.file)

$(MFST_ROOT)/network/ldap/%: ../../ldapcachemgr/%
	$(INS.file)

$(MFST_ROOT)/network/nis/%: ../../ypcmd/%
	$(INS.file)

$(MFST_ROOT)/network/rpc/%: ../../keyserv/%
	$(INS.file)

$(MFST_ROOT)/network/rpc/%: ../../rpcbind/%
	$(INS.file)

$(MFST_ROOT)/system/%: ../../cmd-crypto/scripts/%
	$(INS.file)

$(MFST_ROOT)/system/%: ../../nscd/%
	$(INS.file)

$(MFST_ROOT)/system/%: ../../syslogd/%
	$(INS.file)

$(MFST_ROOT)/system/%: ../../utmpd/%
	$(INS.file)

$(MFST_ROOT)/system/%: ../milestone/%
	$(INS.file)

$(MFST_ROOT)/system/device/%: ../milestone/%
	$(INS.file)

$(MFST_ROOT)/system/filesystem/%: ../milestone/%
	$(INS.file)

$(MFST_ROOT)/system/svc/%: ../milestone/%
	$(INS.file)

FRC:
