#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2014 Nexenta Systems, Inc.
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Joyent, Inc.
# Copyright 2018 Gary Mills
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2019 Peter Tribble
#

include		$(SRC)/Makefile.master

MANSECT=	7

_MANFILES=	Intro.7			\
		acl.7			\
		ad.7			\
		ascii.7			\
		attributes.7		\
		audit_binfile.7		\
		audit_remote.7		\
		audit_syslog.7		\
		brands.7		\
		byteorder.7		\
		cancellation.7		\
		charmap.7		\
		condition.7		\
		crypt_bsdbf.7		\
		crypt_bsdmd5.7		\
		crypt_sha256.7		\
		crypt_sha512.7		\
		crypt_sunmd5.7		\
		crypt_unix.7		\
		device_clean.7		\
		dhcp.7			\
		environ.7		\
		epoll.7			\
		eqn.7			\
		eqnchar.7		\
		eventfd.7		\
		extendedFILE.7		\
		filesystem.7		\
		fnmatch.7		\
		formats.7		\
		fsattr.7		\
		grub.7			\
		gss_auth_rules.7	\
		hal.7			\
		iconv.7			\
		iconv_unicode.7		\
		ieee802.3.7		\
		ieee802.11.7		\
		inotify.7		\
		ipfilter.7		\
		isalist.7		\
		kerberos.7		\
		krb5_auth_rules.7	\
		krb5envvar.7		\
		largefile.7		\
		lf64.7			\
		lfcompile.7		\
		lfcompile64.7		\
		locale.7		\
		lx.7			\
		man.7			\
		mandoc_char.7		\
		mandoc_roff.7		\
		mansun.7		\
		mdoc.7			\
		me.7			\
		mech_spnego.7		\
		mm.7			\
		ms.7			\
		mutex.7			\
		nfssec.7		\
		overlay.7		\
		pam_allow.7		\
		pam_authtok_check.7	\
		pam_authtok_get.7	\
		pam_authtok_store.7	\
		pam_deny.7		\
		pam_dhkeys.7		\
		pam_dial_auth.7		\
		pam_krb5.7		\
		pam_krb5_migrate.7	\
		pam_ldap.7		\
		pam_list.7		\
		pam_passwd_auth.7	\
		pam_rhosts_auth.7	\
		pam_roles.7		\
		pam_sample.7		\
		pam_smb_passwd.7	\
		pam_smbfs_login.7	\
		pam_timestamp.7		\
		pam_tsol_account.7	\
		pam_unix_account.7	\
		pam_unix_auth.7		\
		pam_unix_cred.7		\
		pam_unix_session.7	\
		pkcs11_kernel.7		\
		pkcs11_softtoken.7	\
		pkcs11_tpm.7		\
		privileges.7		\
		prof.7			\
		rbac.7			\
		regex.7			\
		regexp.7		\
		resource_controls.7	\
		security-flags.7	\
		smf.7			\
		smf_bootstrap.7		\
		smf_method.7		\
		smf_restarter.7		\
		smf_security.7		\
		smf_template.7		\
		standards.7		\
		sticky.7		\
		style.7			\
		tbl.7			\
		tecla.7			\
		term.7			\
		threads.7		\
		timerfd.7		\
		trusted_extensions.7	\
		vgrindefs.7		\
		zones.7			\
		zpool-features.7

i386_MANFILES=	beastie.4th.7		\
		brand.4th.7		\
		check-password.4th.7	\
		color.4th.7		\
		delay.4th.7		\
		gptzfsboot.7		\
		isoboot.7		\
		loader.7		\
		loader.4th.7		\
		menu.4th.7		\
		menusets.4th.7		\
		pxeboot.7		\
		version.4th.7

MANLINKS=	ANSI.7		\
		C++.7		\
		C.7		\
		CSI.7		\
		ISO.7		\
		MT-Level.7	\
		POSIX.1.7	\
		POSIX.2.7	\
		POSIX.7		\
		RBAC.7		\
		SUS.7		\
		SUSv2.7		\
		SUSv3.7		\
		SVID.7		\
		SVID3.7		\
		XNS.7		\
		XNS4.7		\
		XNS5.7		\
		XPG.7		\
		XPG3.7		\
		XPG4.7		\
		XPG4v2.7	\
		advance.7	\
		architecture.7	\
		availability.7	\
		compile.7	\
		endian.7	\
		intro.7		\
		pthreads.7	\
		stability.7	\
		standard.7	\
		step.7		\
		teclarc.7

MANFILES=	$(_MANFILES) $($(MACH)_MANFILES)

intro.7		:= LINKSRC = Intro.7

CSI.7		:= LINKSRC = attributes.7
MT-Level.7	:= LINKSRC = attributes.7
architecture.7	:= LINKSRC = attributes.7
availability.7	:= LINKSRC = attributes.7
stability.7	:= LINKSRC = attributes.7
standard.7	:= LINKSRC = attributes.7

endian.7	:= LINKSRC = byteorder.7

RBAC.7		:= LINKSRC = rbac.7

advance.7	:= LINKSRC = regexp.7
compile.7	:= LINKSRC = regexp.7
step.7		:= LINKSRC = regexp.7

ANSI.7		:= LINKSRC = standards.7
C++.7		:= LINKSRC = standards.7
C.7		:= LINKSRC = standards.7
ISO.7		:= LINKSRC = standards.7
POSIX.1.7	:= LINKSRC = standards.7
POSIX.2.7	:= LINKSRC = standards.7
POSIX.7		:= LINKSRC = standards.7
SUS.7		:= LINKSRC = standards.7
SUSv2.7		:= LINKSRC = standards.7
SUSv3.7		:= LINKSRC = standards.7
SVID.7		:= LINKSRC = standards.7
SVID3.7		:= LINKSRC = standards.7
XNS.7		:= LINKSRC = standards.7
XNS4.7		:= LINKSRC = standards.7
XNS5.7		:= LINKSRC = standards.7
XPG.7		:= LINKSRC = standards.7
XPG3.7		:= LINKSRC = standards.7
XPG4.7		:= LINKSRC = standards.7
XPG4v2.7	:= LINKSRC = standards.7

teclarc.7	:= LINKSRC = tecla.7

pthreads.7	:= LINKSRC = threads.7

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
