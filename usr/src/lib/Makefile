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
# Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2020 Joyent, Inc.
# Copyright (c) 2013 Gary Mills
# Copyright (c) 2015 Gary Mills
# Copyright 2022 Garrett D'Amore
# Copyright 2016 Toomas Soome <tsoome@me.com>
# Copyright 2018 Nexenta Systems, Inc.
# Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
# Copyright 2017 RackTop Systems.
# Copyright 2018 Jason King
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

include ../Makefile.master

#	Note that libcurses installs commands along with its library.
#	This is a minor bug which probably should be fixed.
#	Note also that a few extra libraries are kept in cmd source.
#
# Certain libraries are linked with, hence depend on, other libraries.
# Library dependencies are called out explicitly, see "Library
# interdependencies" below.
.PARALLEL:

# Build libc and its dependencies
SUBDIRS=			\
	ssp_ns			\
	crt			\
	../cmd/sgs/libconv	\
	../cmd/sgs/libdl	\
	libc			\
	.WAIT

# Build libraries with lots of dependents
SUBDIRS +=		\
	libm		\
	libmd		\
	libmp		\
	libnsl		\
	libnvpair	\
	libsocket	\
	.WAIT

# Build everything else. Aside from explicit dependencies, all libraries
# are built in parallel.
SUBDIRS +=				\
	../cmd/sendmail/libmilter	\
	../cmd/sgs/libelf	\
	../cmd/sgs/librtld_db	\
	abi		\
	auditd_plugins	\
	brand		\
	c_synonyms	\
	cfgadm_plugins	\
	crypt_modules	\
	extendedFILE	\
	fm		\
	getloginx	\
	gss_mechs/mech_dh	\
	gss_mechs/mech_dummy	\
	gss_mechs/mech_krb5	\
	gss_mechs/mech_spnego	\
	hal		\
	hbaapi		\
	iconv_modules	\
	krb5		\
	libadm		\
	libads		\
	libadt_jni	\
	libadutils	\
	libaio		\
	libavl		\
	libbe		\
	libbrand	\
	libbsdmalloc	\
	libbsm		\
	libc_db		\
	libcfgadm	\
	libcmdutils	\
	libcommputil	\
	libcontract	\
	libcpc		\
	libcrypt	\
	libcryptoutil	\
	libctf		\
	libcurses	\
	libcustr	\
	libdemangle	\
	libdevice	\
	libdevid	\
	libdevinfo	\
	libdhcpagent	\
	libdhcputil	\
	libdisasm	\
	libdiskmgt	\
	libdladm	\
	libdlpi		\
	libdns_sd	\
	libdoor		\
	libdtrace	\
	libdtrace_jni	\
	libdwarf	\
	libefi		\
	libelfsign	\
	libeti		\
	libexacct	\
	libexacct/demo	\
	libfakekernel	\
	libfcoe		\
	libficl		\
	libfru		\
	libfruutils	\
	libfsmgt	\
	libfstyp	\
	libgen		\
	libgrubmgmt	\
	libgss		\
	libhotplug	\
	libidmap	\
	libidspace	\
	libilb		\
	libima		\
	libinetsvc	\
	libinetutil	\
	libinstzones	\
	libintl		\
	libipadm	\
	libipd		\
	libipmi		\
	libipmp		\
	libipp		\
	libipsecutil	\
	libiscsit	\
	libjedec	\
	libkmf		\
	libkrb5		\
	libkstat	\
	libkvm		\
	libldap5	\
	liblgrp		\
	liblm		\
	libm1		\
	libmail		\
	libmalloc	\
	libmapid	\
	libmapmalloc	\
	libmd5		\
	libmlrpc	\
	libmtmalloc	\
	libmvec		\
	libndmp		\
	libnisdb	\
	libnls		\
	libnvme		\
	libnwam		\
	libofmt		\
	libpam		\
	libpcidb	\
	libpcsc		\
	libpctx		\
	libpicl		\
	libpicltree	\
	libpkg		\
	libpool		\
	libproc		\
	libproject	\
	libpthread	\
	libraidcfg	\
	librcm		\
	librename	\
	libreparse	\
	libresolv	\
	libresolv2	\
	librestart	\
	librpcsvc	\
	librsm		\
	librstp		\
	librt		\
	libsasl		\
	libscf		\
	libsched	\
	libsctp		\
	libsec		\
	libsecdb	\
	libsendfile	\
	libsff		\
	libshare	\
	libsip		\
	libsldap	\
	libslp		\
	libsmbfs	\
	libsmbios	\
	libsmedia	\
	libsqlite	\
	libsrpt		\
	libstmf		\
	libstmfproxy	\
	libsun_ima	\
	libsysevent	\
	libtecla	\
	libtermcap	\
	libthread	\
	libtsnet	\
	libtsol		\
	libumem		\
	libutempter	\
	libuuid		\
	libuutil	\
	libvolmgt	\
	libvrrpadm	\
	libvscan	\
	libw		\
	libwrap		\
	libxcurses	\
	libxcurses2	\
	libxnet		\
	libzfs		\
	libzfsbootenv	\
	libzfs_core	\
	libzfs_jni	\
	libzonecfg	\
	libzoneinfo	\
	libzonestat	\
	libzpool	\
	libzutil	\
	madv		\
	mpapi		\
	mpss		\
	nametoaddr	\
	nsswitch	\
	pam_modules	\
	passwdutil	\
	pkcs11		\
	policykit	\
	print		\
	pylibbe		\
	pysolaris	\
	pyzfs		\
	raidcfg_plugins	\
	rpcsec_gss	\
	sasl_plugins	\
	scsi		\
	smbclnt		\
	smbsrv		\
	smhba		\
	sun_fc		\
	sun_sas		\
	udapl		\
	varpd		\
	watchmalloc	\
	$($(MACH)_SUBDIRS)

i386_SUBDIRS=		\
	lib9p		\
	libfdisk	\
	libppt		\
	libsaveargs	\
	libvmm		\
	libvmmapi

sparc_SUBDIRS=		\
	libds		\
	libdscp		\
	libprtdiag	\
	libprtdiag_psr	\
	libpri		\
	librsc		\
	storage		\
	libpcp		\
	libtsalarm	\
	libv12n

#
# Create a special version of $(SUBDIRS) with no .WAIT's, for use with the
# clean and clobber targets (for more information, see those targets, below).
#
NOWAIT_SUBDIRS= $(SUBDIRS:.WAIT=)

DCSUBDIRS=

MSGSUBDIRS=		\
	abi		\
	auditd_plugins	\
	brand		\
	cfgadm_plugins	\
	gss_mechs/mech_dh	\
	gss_mechs/mech_krb5	\
	krb5		\
	libbsm		\
	libc		\
	libcfgadm	\
	libcontract	\
	libcurses	\
	libdhcputil	\
	libdiskmgt	\
	libdladm	\
	libgrubmgmt	\
	libgss		\
	libidmap	\
	libilb		\
	libinstzones	\
	libipadm	\
	libipmp		\
	libipsecutil	\
	libldap5	\
	libnsl		\
	libnwam		\
	libofmt		\
	libpam		\
	libpicl		\
	libpkg		\
	libpool		\
	libreparse	\
	libsasl		\
	libscf		\
	libsecdb	\
	libshare	\
	libsldap	\
	libslp		\
	libsmbfs	\
	libsmedia	\
	libtsol		\
	libuutil	\
	libvrrpadm	\
	libvscan	\
	libzfs		\
	libzonecfg	\
	madv		\
	mpss		\
	pam_modules	\
	pyzfs		\
	rpcsec_gss	\
	$($(MACH)_MSGSUBDIRS)

sparc_MSGSUBDIRS=	\
	libprtdiag	\
	libprtdiag_psr

i386_MSGSUBDIRS= libfdisk

HDRSUBDIRS=				\
	../cmd/sendmail/libmilter	\
	auditd_plugins	\
	fm		\
	hal		\
	hbaapi		\
	libads		\
	libbrand	\
	libbsm		\
	libc		\
	libcmdutils	\
	libcommputil	\
	libcontract	\
	libcpc		\
	libcryptoutil	\
	libctf		\
	libcurses	\
	libcustr	\
	libdemangle	\
	libdevice	\
	libdevid	\
	libdevinfo	\
	libdhcpagent	\
	libdhcputil	\
	libdisasm	\
	libdiskmgt	\
	libdladm	\
	libdlpi		\
	libdns_sd	\
	libdtrace	\
	libdtrace_jni	\
	libelfsign	\
	libeti		\
	libfakekernel	\
	libfcoe		\
	libfru		\
	libfstyp	\
	libgen		\
	libgrubmgmt	\
	libidmap	\
	libidspace	\
	libilb		\
	libima		\
	libinetsvc	\
	libinetutil	\
	libinstzones	\
	libipadm	\
	libipd		\
	libipmi		\
	libipmp		\
	libipp		\
	libipsecutil	\
	libiscsit	\
	libkrb5		\
	libkstat	\
	libkvm		\
	libmail		\
	libmapid	\
	libmd		\
	libmlrpc	\
	libmtmalloc	\
	libndmp		\
	libnsl		\
	libnvme		\
	libnvpair	\
	libnwam		\
	libofmt		\
	libpam		\
	libpcidb	\
	libpcsc		\
	libpctx		\
	libpicl		\
	libpicltree	\
	libpool		\
	libproc		\
	libraidcfg	\
	librcm		\
	librename	\
	libreparse	\
	librestart	\
	librpcsvc	\
	librsm		\
	librstp		\
	libsasl		\
	libscf		\
	libsec		\
	libsff		\
	libshare	\
	libsip		\
	libslp		\
	libsmbfs	\
	libsmbios	\
	libsmedia	\
	libsocket	\
	libsqlite	\
	libsrpt		\
	libstmf		\
	libstmfproxy	\
	libsun_ima	\
	libsysevent	\
	libtecla	\
	libtermcap	\
	libtsnet	\
	libtsol		\
	libumem		\
	libutempter	\
	libuutil	\
	libvolmgt	\
	libvrrpadm	\
	libvscan	\
	libwrap		\
	libxcurses2	\
	libzfs		\
	libzfs_core	\
	libzfs_jni	\
	libzoneinfo	\
	libzonestat	\
	mpapi		\
	passwdutil	\
	pkcs11		\
	policykit	\
	scsi		\
	smbsrv		\
	smhba		\
	udapl		\
	varpd		\
	$($(MACH)_HDRSUBDIRS)

i386_HDRSUBDIRS=	\
	lib9p		\
	libfdisk	\
	libppt		\
	libsaveargs	\
	libvmm		\
	libvmmapi

sparc_HDRSUBDIRS=	\
	libds		\
	libdscp		\
	libpri		\
	libv12n		\
	storage

all :=		TARGET= all
check :=	TARGET= check
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
install_h :=	TARGET= install_h
_dc :=		TARGET= _dc
_msg :=		TARGET= _msg

.KEEP_STATE:

#
# For the all and install targets, we clearly must respect library
# dependencies so that the libraries link correctly.  However, for
# the remaining targets (check, clean, clobber, install_h, _dc
# and _msg), libraries do not have any dependencies on one another
# and thus respecting dependencies just slows down the build.
# As such, for these rules, we use pattern replacement to explicitly
# avoid triggering the dependency information.  Note that for clean and
# clobber, we must use $(NOWAIT_SUBDIRS) rather than
# $(SUBDIRS), to prevent `.WAIT' from expanding to `.WAIT-nodepend'.
#

all:			$(SUBDIRS)

install:		$(SUBDIRS) .WAIT install_extra

# extra libraries kept in other source areas
install_extra:
	@cd ../cmd/sgs; pwd; $(MAKE) install_lib
	@pwd

clean clobber:		$(NOWAIT_SUBDIRS:%=%-nodepend)


install_h check:	$(HDRSUBDIRS:%=%-nodepend)

_msg:			$(MSGSUBDIRS:%=%-nodepend) .WAIT _dc

_dc:			$(DCSUBDIRS:%=%-nodepend)

# Library interdependencies are called out explicitly here.
../cmd/sgs/libconv: crt
../cmd/sgs/libdl: crt
libc:		../cmd/sgs/libconv ../cmd/sgs/libdl

libm:		libc
libmd:		libc
libmp:		libc
libnsl:		libc libmd libmp
libnvpair:	libc libnsl
libsocket:	libc libnsl

basedeps:	libc libm libmd libmp libnsl libnvpair libsocket
basedeps :=	TARGET=install

# The following dependencies are currently required by libdbus-1 and should
# be used for anything linking against it.
dbusdeps:	libsecdb libtsol libinetutil libscf libuutil libgen libsmbios \
		libbsm

# The following dependencies don't need to be listed below as they are built
# before everything else:
# libc libm libmd libmp libnsl libnvpair libsocket
../cmd/sendmail/libmilter:	libsocket libnsl
abi:		libctf libmapmalloc libproc
auditd_plugins: libbsm libsecdb libgss libmtmalloc
brand:		libzonecfg libmapmalloc
cfgadm_plugins:	libdevice libdevinfo libhotplug librcm hbaapi libkstat libscf
fm:		libexacct libipmi libzfs scsi libdevinfo libdevid libcfgadm \
		libcontract libsysevent ../cmd/sgs/libelf libdladm libsff \
		libpcidb libdiskmgt libjedec libnvme
$(SPARC_BLD)fm:	libpri
gss_mechs/mech_dh: libgss
gss_mechs/mech_dummy: libgss
gss_mechs/mech_krb5: libgss libresolv2 pkcs11 libkstat
gss_mechs/mech_spnego: gss_mechs/mech_krb5
hal:		dbusdeps
krb5:		gss_mechs/mech_krb5 libtecla libldap5
lib9p:		libsec libcustr
libads:		libnsl
libadt_jni:	libbsm
libadutils:	libldap5 libresolv2
libbe:		libzfs libinstzones libuuid libgen libdevinfo libefi libficl \
		libzfsbootenv
libbsm:		libinetutil libscf libsecdb libtsol
libcfgadm:	libdevinfo
libcontract:	libnvpair
libcmdutils:	libavl libnvpair
libcpc:		libpctx
libcrypt:	libgen
libctf:		libavl libdwarf
libdemangle:	libcustr
libdevice:	libnvpair
libdevid:	libdevinfo
libdevinfo:	libsec libgen
libdhcpagent:	libdhcputil libuuid libdlpi libcontract
libdhcputil:	libgen libinetutil libdlpi
libdiskmgt:	libdevid libdevinfo libadm libefi libkstat libsysevent
$(INTEL_BLD)libdiskmgt: libfdisk
libdladm:	libdevinfo libinetutil libscf librcm libexacct libkstat \
		libpool varpd
libdlpi:	libinetutil libdladm
libds:		libsysevent
libdtrace:	libproc libgen libctf libmapmalloc
libdtrace_jni:	libuutil libdtrace
libdwarf:	../cmd/sgs/libelf
libefi:		libuuid libsmbios
libelfsign:	libcryptoutil libkmf ../cmd/sgs/libelf
libeti:		libcurses
libexacct/demo:	libexacct libproject
libfakekernel:	libumem libcryptoutil
libfcoe:	libdladm
libficl:	libuuid libumem
libfru:		libfruutils
libfsmgt:	libkstat
libgrubmgmt:	libdevinfo libzfs libfstyp libefi
$(INTEL_BLD)libgrubmgmt: libfdisk
libidmap:	libavl libuutil
libidspace:	libumem
libinetsvc:	libscf
libinetutil:	libsocket
libinstzones:	libzonecfg libcontract
libipadm:	libinetutil libdlpi libdhcpagent libdladm libsecdb libdhcputil \
		libcmdutils libipmp
libipmi:	libm libnvpair libsocket libnsl
libipmp:	libinetutil
libipsecutil:	libtecla libtsol libkmf
libiscsit:	libstmf libuuid
libhotplug:	libnvpair
libkmf:		libcryptoutil pkcs11 libcustr
libkvm:		../cmd/sgs/libelf
libldap5:	libsasl
libmapid:	libresolv2 libscf
libmlrpc:	libsmbfs libuuid
libndmp:	libscf
libnisdb:	libldap5
libnvme:	libdevinfo libnvpair
libnwam:	libscf libbsm libdladm libipadm
libpcp:		libumem libdevinfo
libpctx:	libproc
libpkg:		libscf libadm
libpool:	libscf libexacct
libppt:		libpcidb libdevinfo libcmdutils
libproc:	../cmd/sgs/librtld_db ../cmd/sgs/libelf libctf
$(INTEL_BLD)libproc: libsaveargs
libproject:	libpool libproc libsecdb
libprtdiag:	libkstat libdevinfo
libprtdiag_psr:	libprtdiag
libraidcfg:	libdevinfo
librcm:		libnvpair
librestart:	libuutil libscf libpool libproject libsecdb libsysevent
libsasl:	libgss pkcs11
libsaveargs:	libdisasm
libscf:		libuutil libgen libnsl libnvpair libsmbios
libsec:		libavl libidmap
libsecdb:	libnsl
libsff:		libnvpair
libshare:	libscf libzfs libuuid libfsmgt libsecdb libumem libsmbfs
libsip:		libmd5
libsldap:	libldap5 libscf
libsmbfs:	libkrb5 libsec libidmap pkcs11
libsmbios:	libdevinfo
libsrpt:	libstmf
libstmf:	libscf
libstmfproxy:	libstmf libpthread
libsun_ima:	libdevinfo libsysevent
libsysevent:	libsecdb
libtecla:	libcurses
libtermcap:	libcurses
libtsalarm:	libpcp
libtsnet:	libtsol libsecdb
libtsol:	libsecdb
libuuid:	libdlpi
libv12n:	libds libuuid
libvmm:		libvmmapi
libvolmgt:	libadm
libvrrpadm:	libdladm libscf
libvscan:	libscf libsecdb
libzfs:		libdevid libgen libuutil libavl libefi libidmap \
		libumem libtsol libzfs_core libcryptoutil pkcs11 libmd libzutil
libzfsbootenv:	libzfs libnvpair
libzfs_core:	libnvpair
libzfs_jni:	libdiskmgt libzfs libzutil
libzonecfg:	libuuid libsysevent libsec libbrand libpool libscf libproc \
		libuutil libbsm libsecdb
libzonestat:	libcmdutils libumem
libzpool:	libavl libumem libcmdutils libsysevent libfakekernel libzutil
libzutil:	libadm libavl libdevid libefi
madv:		libgen
mpapi:		libpthread libdevinfo libsysevent
mpss:		libgen
nsswitch:	libadutils libidmap libdns_sd libscf libldap5 libsldap
pam_modules:	libproject passwdutil smbsrv libtsnet libpam libbsm libsecdb
passwdutil:	libsldap
pkcs11:		libcryptoutil libgen libuuid
policykit:	dbusdeps
print:		libldap5 libmd5 libsendfile
pylibbe:	libbe libzfs
pysolaris:	libsec libidmap
pyzfs:		libzfs
raidcfg_plugins: libraidcfg librcm libcfgadm libpicl libpicltree
rpcsec_gss:	libgss
sasl_plugins:	pkcs11 libgss libsasl
scsi:		libfru libumem libdevid libdevinfo
smbclnt:	libfakekernel pkcs11
smbsrv:		libxnet libpthread librt libshare libidmap pkcs11 libsqlite \
		libcryptoutil libreparse libcmdutils libresolv2 libsmbfs \
		libuuid libfakekernel libads libgss libldap5 krb5 libmlrpc
storage:	libdevice libdevinfo libdevid
sun_fc:		libdevinfo libsysevent
sun_sas:	libdevinfo libsysevent libkstat libdevid
udapl:		libdevinfo libdladm
varpd:		libavl libidspace libumem libnsl libnvpair libmd5 librename \
		libcustr

#
# The reason this rule checks for the existence of the
# Makefile is that some of the directories do not exist
# in certain situations (e.g., exportable source builds,
# OpenSolaris).
#
$(SUBDIRS): FRC
	cd $@; pwd; $(MAKE) $(TARGET)

$(SUBDIRS:%=%-nodepend):
	cd $(@:%-nodepend=%); pwd; $(MAKE) $(TARGET)

FRC:
