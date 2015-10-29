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

# Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright (c) 2012, Joyent, Inc. All rights reserved.
# Copyright (c) 2013 Gary Mills
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
# Copyright (c) 2015 Gary Mills

include ../Makefile.master

#	Note that libcurses installs commands along with its library.
#	This is a minor bug which probably should be fixed.
#	Note also that a few extra libraries are kept in cmd source.
#
# Certain libraries are linked with, hence depend on, other libraries.
#
# Although we have historically used .WAIT to express dependencies, it
# reduces the amount of parallelism and thus lengthens the time it
# takes to build the libraries.  Thus, we now require that any new
# libraries explicitly call out their dependencies.  Eventually, all
# the library dependencies will be called out explicitly.  See
# "Library interdependencies" near the end of this file.
#
# Aside from explicit dependencies (and legacy .WAITs), all libraries
# are built in parallel.
#
.PARALLEL:

SUBDIRS= \
	common			.WAIT	\
	../cmd/sgs/libconv		\
	../cmd/sgs/libdl	.WAIT

SUBDIRS += \
	libc			.WAIT	\
	../cmd/sgs/libelf	.WAIT	\
	c_synonyms			\
	libmd				\
	libmd5				\
	librsm				\
	libmp			.WAIT	\
	libnsl			\
	libsecdb		.WAIT	\
	librpcsvc			\
	libsocket		.WAIT	\
	libsctp			\
	libsip			\
	libcommputil		\
	libresolv			\
	libresolv2		.WAIT	\
	libw			.WAIT	\
	libintl			.WAIT	\
	../cmd/sgs/librtld_db	\
	libaio			\
	libast			\
	libdll			\
	libcmd			\
	libshell		\
	libsum			\
	librt			\
	libadm			\
	libctf			\
	libdtrace		\
	libdtrace_jni		\
	libcurses		\
	libtermcap		\
	libgen			\
	libgss			\
	libpam			\
	libuuid			\
	libthread		\
	libpthread	.WAIT	\
	libslp		\
	libbsdmalloc	\
	libdoor		\
	libdevinfo	\
	libdladm	\
	libdlpi		\
	libeti		\
	libcrypt	\
	libdns_sd	\
	libefi		\
	libfstyp	\
	libwanboot	\
	libwanbootutil	\
	libcryptoutil	\
	libinetutil	\
	libipadm	\
	libipd		\
	libipmp		\
	libiscsit	\
	libkmf		\
	libkstat	\
	libkvm		\
	liblm		\
	libmalloc	\
	libmapmalloc	\
	libmtmalloc	\
	libnls		\
	libnwam		\
	libsmbios	\
	libtecla	\
	libumem		\
	libnvpair	.WAIT	\
	libexacct	\
	libsasl		\
	libldap5	\
	libsldap	.WAIT	\
	libbsm		\
	libsys		\
	libsysevent	\
	libnisdb	\
	libpool		\
	libpp		\
	libproc		\
	libproject	\
	libsendfile	\
	nametoaddr	\
	ncad_addr	\
	hbaapi		\
	smhba		\
	sun_fc		\
	sun_sas		\
	gss_mechs/mech_krb5	.WAIT	\
	libkrb5	.WAIT	\
	krb5	.WAIT	\
	libsmbfs	\
	libfcoe		\
	libsrpt		\
	libstmf		\
	libstmfproxy	\
	libnsctl	\
	libunistat	\
	libdscfg	\
	librdc		\
	libinstzones	\
	libpkg		\
	libpcidb	\
	libm1		\
	libm		\
	libmvec


SUBDIRS += \
	passwdutil	\
	pam_modules	\
	crypt_modules	\
	libadt_jni	\
	abi		\
	auditd_plugins	\
	libvolmgt	\
	libdevice	\
	libdevid	\
	libc_db		\
	libndmp		\
	libsec		\
	libtnfprobe	\
	libtnf		\
	libtnfctl	\
	libdhcpagent	\
	libdhcputil	\
	libxnet		\
	libipsecutil	\
	nsswitch	\
	print		\
	libuutil	\
	libscf		\
	libinetsvc	\
	librestart	\
	libsched	\
	libelfsign	\
	pkcs11		.WAIT	\
	libpctx		.WAIT	\
	libcpc		\
	getloginx	\
	watchmalloc	\
	extendedFILE	\
	madv		\
	mpss		\
	libdisasm	\
	libwrap		\
	libxcurses	\
	libxcurses2	\
	libbrand	.WAIT   \
	libzonecfg	\
	libzoneinfo	\
	libzonestat	\
	libtsnet	\
	libtsol		\
	gss_mechs/mech_spnego	\
	gss_mechs/mech_dummy	\
	gss_mechs/mech_dh	\
	rpcsec_gss	\
	libraidcfg	.WAIT	\
	librcm		.WAIT	\
	libcfgadm	.WAIT	\
	libpicl		.WAIT	\
	libpicltree	.WAIT \
	raidcfg_plugins	\
	cfgadm_plugins	\
	libmail		\
	lvm		\
	libsmedia	\
	libipp		\
	libdiskmgt	\
	liblgrp		\
	libfsmgt	\
	fm		\
	libavl		\
	libcmdutils	\
	libcontract	\
	../cmd/sendmail/libmilter	\
	sasl_plugins	\
	udapl		\
	libzpool	\
	libzfs_core	\
	libzfs		\
	libbe		\
	pylibbe		\
	libzfs_jni	\
	pyzfs		\
	pysolaris	\
	libmapid	\
	brand		\
	policykit	\
	hal		\
	libshare	\
	libsqlite	\
	libidmap	\
	libads		\
	libadutils	\
	libipmi		\
	libexacct/demo	\
	libvrrpadm	\
	libvscan	\
	libgrubmgmt	\
	libfakekernel	\
	smbsrv		\
	libilb		\
	scsi		\
	libima		\
	libsun_ima	\
	mpapi		\
	librstp		\
	libreparse	\
	libhotplug	\
	libfruutils	.WAIT	\
	libfru		\
	$($(MACH)_SUBDIRS)

i386_SUBDIRS=		\
	libfdisk	\
	libsaveargs

sparc_SUBDIRS= .WAIT	\
	efcode		\
	libds		\
	libdscp		\
	libprtdiag	.WAIT	\
	libprtdiag_psr	\
	libpri		\
	librsc		\
	storage		\
	libpcp		\
	libtsalarm	\
	libv12n

FM_sparc_DEPLIBS= libpri

fm:			\
	libexacct	\
	libipmi		\
	libzfs		\
	scsi		\
	$(FM_$(MACH)_DEPLIBS)

#
# Create a special version of $(SUBDIRS) with no .WAIT's, for use with the
# clean and clobber targets (for more information, see those targets, below).
#
NOWAIT_SUBDIRS= $(SUBDIRS:.WAIT=)

DCSUBDIRS =		\
	lvm

MSGSUBDIRS=		\
	abi		\
	auditd_plugins	\
	brand		\
	cfgadm_plugins	\
	gss_mechs/mech_dh	\
	gss_mechs/mech_krb5	\
	krb5		\
	libast		\
	libbsm		\
	libc		\
	libcfgadm	\
	libcmd		\
	libcontract	\
	libcurses	\
	libdhcputil	\
	libipsecutil	\
	libdiskmgt	\
	libdladm	\
	libdll		\
	libgrubmgmt	\
	libgss		\
	libidmap	\
	libipmp		\
	libilb		\
	libinetutil	\
	libinstzones	\
	libipadm	\
	libnsl		\
	libnwam		\
	libpam		\
	libpicl		\
	libpool		\
	libpkg		\
	libpp		\
	libscf		\
	libsasl		\
	libldap5	\
	libsecdb	\
	libshare	\
	libshell	\
	libsldap	\
	libslp		\
	libsmbfs	\
	libsmedia	\
	libsum		\
	libtsol		\
	libuutil	\
	libvrrpadm	\
	libvscan	\
	libwanboot	\
	libwanbootutil	\
	libzfs		\
	libzonecfg	\
	lvm		\
	madv		\
	mpss		\
	pam_modules	\
	pyzfs		\
	pysolaris	\
	rpcsec_gss	\
	libreparse
MSGSUBDIRS += \
	$($(MACH)_MSGSUBDIRS)

sparc_MSGSUBDIRS=	\
	libprtdiag	\
	libprtdiag_psr

i386_MSGSUBDIRS= libfdisk

HDRSUBDIRS=		\
	auditd_plugins	\
	libads		\
	libast		\
	libbrand	\
	libbsm		\
	libc		\
	libcmd		\
	libcmdutils	\
	libcommputil	\
	libcontract	\
	libcpc		\
	libctf		\
	libcurses	\
	libtermcap	\
	libcryptoutil	\
	libdevice	\
	libdevid	\
	libdevinfo	\
	libdiskmgt	\
	libdladm	\
	libdll		\
	libdlpi		\
	libdhcpagent	\
	libdhcputil	\
	libdisasm	\
	libdns_sd	\
	libdscfg	\
	libdtrace	\
	libdtrace_jni	\
	libelfsign	\
	libeti		\
	libfakekernel	\
	libfru		\
	libfstyp	\
	libgen		\
	libipadm	\
	libipd		\
	libipsecutil	\
	libinetsvc	\
	libinetutil	\
	libinstzones	\
	libipmi		\
	libipmp		\
	libipp		\
	libiscsit	\
	libkstat	\
	libkvm		\
	libmail		\
	libmd		\
	libmtmalloc	\
	libndmp		\
	libnvpair	\
	libnsctl	\
	libnsl		\
	libnwam		\
	libpam		\
	libpcidb	\
	libpctx		\
	libpicl		\
	libpicltree	\
	libpool		\
	libpp		\
	libproc		\
	libraidcfg	\
	librcm		\
	librdc		\
	libscf		\
	libsip		\
	libsmbios	\
	librestart	\
	librpcsvc	\
	librsm		\
	librstp		\
	libsasl		\
	libsec		\
	libshell	\
	libslp		\
	libsmedia	\
	libsocket	\
	libsqlite	\
	libfcoe		\
	libsrpt		\
	libstmf		\
	libstmfproxy	\
	libsum		\
	libsysevent	\
	libtecla	\
	libtnf		\
	libtnfctl	\
	libtnfprobe	\
	libtsnet	\
	libtsol		\
	libvrrpadm	\
	libvolmgt	\
	libumem		\
	libunistat	\
	libuutil	\
	libwanboot	\
	libwanbootutil	\
	libwrap		\
	libxcurses2	\
	libzfs		\
	libzfs_core	\
	libzfs_jni	\
	libzoneinfo	\
	libzonestat	\
	hal		\
	policykit	\
	lvm		\
	pkcs11		\
	passwdutil	\
	../cmd/sendmail/libmilter	\
	fm		\
	udapl		\
	libmapid	\
	libkrb5		\
	libsmbfs	\
	libshare	\
	libidmap	\
	libvscan	\
	libgrubmgmt	\
	smbsrv		\
	libilb		\
	scsi		\
	hbaapi		\
	smhba		\
	libima		\
	libsun_ima	\
	mpapi		\
	libreparse	\
	$($(MACH)_HDRSUBDIRS)

i386_HDRSUBDIRS=	\
	libfdisk	\
	libsaveargs

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
lint :=		TARGET= lint
_dc :=		TARGET= _dc
_msg :=		TARGET= _msg

.KEEP_STATE:

#
# For the all and install targets, we clearly must respect library
# dependencies so that the libraries link correctly.  However, for
# the remaining targets (check, clean, clobber, install_h, lint, _dc
# and _msg), libraries do not have any dependencies on one another
# and thus respecting dependencies just slows down the build.
# As such, for these rules, we use pattern replacement to explicitly
# avoid triggering the dependency information.  Note that for clean,
# clobber and lint, we must use $(NOWAIT_SUBDIRS) rather than
# $(SUBDIRS), to prevent `.WAIT' from expanding to `.WAIT-nodepend'.
#

all:			$(SUBDIRS)

install:		$(SUBDIRS) .WAIT install_extra

# extra libraries kept in other source areas
install_extra:
	@cd ../cmd/sgs; pwd; $(MAKE) install_lib
	@pwd

clean clobber lint:	$(NOWAIT_SUBDIRS:%=%-nodepend)

install_h check:	$(HDRSUBDIRS:%=%-nodepend)

_msg:			$(MSGSUBDIRS:%=%-nodepend) .WAIT _dc

_dc:			$(DCSUBDIRS:%=%-nodepend)

#
# Library interdependencies are called out explicitly here
#
auditd_plugins: libbsm libnsl libsecdb
krb5:		gss_mechs/mech_krb5
gss_mechs/mech_krb5:	libgss libnsl libsocket libresolv pkcs11
gss_mechs/mech_spnego:	gss_mechs/mech_krb5
libadt_jni:	libbsm
libast: 	libsocket libm
libadutils: 	libldap5 libresolv libsocket libnsl
nsswitch:	libadutils libidmap
libbe: 		libzfs
libbsm:		libtsol
libcmd: 	libsum libast libsocket libnsl
libcmdutils:	libavl libnvpair
libcontract:	libnvpair
libcpc:		libdevinfo
libdevid:	libdevinfo
libdevinfo:	libnvpair libsec
libdhcpagent:	libsocket libdhcputil libuuid libdlpi libcontract
libdhcputil:	libnsl libgen libinetutil libdlpi
libdladm:	libdevinfo libinetutil libsocket libscf librcm libnvpair \
		libexacct libnsl libkstat libcurses
libdevice:	libnvpair
libdll: 	libast
libdlpi:	libinetutil libdladm
libds:		libsysevent
libdscfg:	libnsctl libunistat libsocket libnsl
libdtrace:	libproc libgen libctf libmapmalloc
libdtrace_jni:	libuutil libdtrace
libefi:		libuuid
libfcoe:	libdladm
libfstyp:	libnvpair
libelfsign:	libcryptoutil libkmf
libidmap:	libadutils libldap5 libavl libsldap libuutil
libipadm:	libnsl libinetutil libsocket libdlpi libnvpair libdhcpagent \
		libdladm libsecdb
libiscsit:	libc libnvpair libstmf libuuid libnsl
libkmf:		libcryptoutil pkcs11
libm:		libc
libm1:		libc libm
libmvec:	libc libm
libnsl:		libmd5
libmapid:	libresolv
libnisdb:	libnsl libldap5
librcm:		libnvpair
librdc:		libsocket libnsl libnsctl libunistat libdscfg
libuuid:	libdlpi
libinetutil:	libsocket
libipsecutil:	libtecla libsocket
libinstzones:	libzonecfg libcontract
libpkg:		libwanboot libscf libadm
libnwam:	libscf libbsm libdladm
libsecdb:	libnsl
libsasl:	libgss libsocket pkcs11 libmd
sasl_plugins:	pkcs11 libgss libsocket libsasl
libsctp:	libsocket
libshell:	libast libcmd libdll libsocket libsecdb libm
libsip:		libmd5
libsmbfs:	libcmdutils libsocket libnsl libkrb5 libsec libidmap
libsocket:	libnsl
libstmfproxy: 	libstmf libsocket libnsl libpthread
libsum: 	libast
libsysevent:	libsecdb libnvpair
libldap5:	libsasl libsocket libnsl libmd
libsldap:	libldap5 libtsol libnsl libc libscf libresolv
libpool:	libnvpair libexacct
libpp:		libast
libzonecfg:	libc libsocket libnsl libuuid libnvpair libsysevent libsec \
		libbrand libpool libscf
libproc:	../cmd/sgs/librtld_db ../cmd/sgs/libelf libctf libsaveargs
libproject:	libpool libproc libsecdb
libtermcap:	libcurses
libtsnet:	libnsl libtsol libsecdb
libwrap:	libnsl libsocket
libwanboot:	libnvpair libresolv libnsl libsocket libdevinfo libinetutil \
		libdhcputil
libwanbootutil:	libnsl
pam_modules:	libproject passwdutil smbsrv libtsnet
libscf:		libuutil libmd libgen libsmbios libnsl libnvpair
libinetsvc:	libscf
librestart:	libuutil libscf libpool libproject libsecdb libnvpair
libsaveargs:	libdisasm
../cmd/sgs/libdl:	../cmd/sgs/libconv
../cmd/sgs/libelf:	../cmd/sgs/libconv
passwdutil:	libsldap
pkcs11:		libcryptoutil libmd
#		Adding libuuid or libdladm results in a circular dependancy
print:		libldap5
udapl/udapl_tavor:	udapl/libdat
libzfs:		libdevid libgen libnvpair libuutil \
		libadm libavl libefi libidmap libmd libzfs_core libm
libzfs_core:	libnvpair
libzfs_jni:	libdiskmgt libnvpair libzfs
libzpool:	libavl libumem libnvpair libcmdutils
libsec:		libavl libidmap
brand:		libc libsocket
libshare:	libscf libzfs libuuid libfsmgt libsecdb libumem libsmbfs
libexacct/demo:	libexacct libproject libsocket libnsl
libtsalarm:	libpcp
smbsrv:		libsocket libnsl libmd libxnet libpthread librt \
		libshare libidmap pkcs11 libsqlite libcryptoutil \
		libreparse libcmdutils libresolv libsmbfs libuuid \
		libfakekernel libads
libv12n:	libds libuuid
libvrrpadm:	libsocket libdladm libscf
libvscan:	libscf
libfru:		libfruutils
scsi:		libnvpair libfru
mpapi:		libpthread libdevinfo libsysevent libnvpair
sun_fc:		libdevinfo libsysevent libnvpair
libsun_ima:	libdevinfo libsysevent libnsl
sun_sas:	libdevinfo libsysevent libnvpair libkstat libdevid
libgrubmgmt:	libdevinfo libzfs libfstyp
pylibbe: 	libbe libzfs
pyzfs:		libnvpair libzfs
pysolaris:	libsec libidmap
libreparse:	libnvpair
libhotplug:	libnvpair
cfgadm_plugins:	libhotplug
libilb:		libsocket
libipmi:	libm
libprtdiag:	libm
libsqlite:	libm
libstmf:	libm
libvscan: 	libm


$(INTEL_BUILD)libdiskmgt:libfdisk

#
# The reason this rule checks for the existence of the
# Makefile is that some of the directories do not exist
# in certain situations (e.g., exportable source builds,
# OpenSolaris).
#
$(SUBDIRS): FRC
	@if [ -f $@/Makefile  ]; then \
		cd $@; pwd; $(MAKE) $(TARGET); \
	else \
		true; \
	fi

$(SUBDIRS:%=%-nodepend):
	@if [ -f $(@:%-nodepend=%)/Makefile  ]; then \
		cd $(@:%-nodepend=%); pwd; $(MAKE) $(TARGET); \
	else \
		true; \
	fi

FRC:
