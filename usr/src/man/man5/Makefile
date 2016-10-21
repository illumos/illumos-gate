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
# Copyright (c) 2015, Joyent, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT=	5

MANFILES=	Intro.5			\
		acl.5			\
		ad.5			\
		ascii.5			\
		attributes.5		\
		audit_binfile.5		\
		audit_remote.5		\
		audit_syslog.5		\
		brands.5		\
		byteorder.5		\
		cancellation.5		\
		charmap.5		\
		condition.5		\
		crypt_bsdbf.5		\
		crypt_bsdmd5.5		\
		crypt_sha256.5		\
		crypt_sha512.5		\
		crypt_sunmd5.5		\
		crypt_unix.5		\
		device_clean.5		\
		dhcp.5			\
		environ.5		\
		epoll.5			\
		eqn.5			\
		eqnchar.5		\
		eventfd.5		\
		extendedFILE.5		\
		filesystem.5		\
		fnmatch.5		\
		formats.5		\
		fsattr.5		\
		grub.5			\
		gss_auth_rules.5	\
		hal.5			\
		iconv.5			\
		iconv_unicode.5		\
		ieee802.3.5		\
		ieee802.11.5		\
		ipfilter.5		\
		isalist.5		\
		kerberos.5		\
		krb5_auth_rules.5	\
		krb5envvar.5		\
		largefile.5		\
		lf64.5			\
		lfcompile.5		\
		lfcompile64.5		\
		locale.5		\
		man.5			\
		mandoc_char.5		\
		mandoc_roff.5		\
		mdoc.5			\
		me.5			\
		mech_spnego.5		\
		mm.5			\
		ms.5			\
		mutex.5			\
		nfssec.5		\
		pam_allow.5		\
		pam_authtok_check.5	\
		pam_authtok_get.5	\
		pam_authtok_store.5	\
		pam_deny.5		\
		pam_dhkeys.5		\
		pam_dial_auth.5		\
		pam_krb5.5		\
		pam_krb5_migrate.5	\
		pam_ldap.5		\
		pam_list.5		\
		pam_passwd_auth.5	\
		pam_rhosts_auth.5	\
		pam_roles.5		\
		pam_sample.5		\
		pam_smb_passwd.5	\
		pam_smbfs_login.5	\
		pam_timestamp.5		\
		pam_tsol_account.5	\
		pam_unix_account.5	\
		pam_unix_auth.5		\
		pam_unix_cred.5		\
		pam_unix_session.5	\
		pkcs11_kernel.5		\
		pkcs11_softtoken.5	\
		pkcs11_tpm.5		\
		privileges.5		\
		prof.5			\
		rbac.5			\
		regex.5			\
		regexp.5		\
		resource_controls.5	\
		security-flags.5	\
		smf.5			\
		smf_bootstrap.5		\
		smf_method.5		\
		smf_restarter.5		\
		smf_security.5		\
		smf_template.5		\
		standards.5		\
		sticky.5		\
		tbl.5			\
		tecla.5			\
		term.5			\
		threads.5		\
		timerfd.5		\
		trusted_extensions.5	\
		vgrindefs.5		\
		zones.5			\
		zpool-features.5

MANLINKS=	ANSI.5		\
		C++.5		\
		C.5		\
		CSI.5		\
		ISO.5		\
		MT-Level.5	\
		POSIX.1.5	\
		POSIX.2.5	\
		POSIX.5		\
		RBAC.5		\
		SUS.5		\
		SUSv2.5		\
		SUSv3.5		\
		SVID.5		\
		SVID3.5		\
		XNS.5		\
		XNS4.5		\
		XNS5.5		\
		XPG.5		\
		XPG3.5		\
		XPG4.5		\
		XPG4v2.5	\
		advance.5	\
		architecture.5	\
		availability.5	\
		compile.5	\
		endian.5	\
		intro.5		\
		pthreads.5	\
		stability.5	\
		standard.5	\
		step.5		\
		teclarc.5

intro.5		:= LINKSRC = Intro.5

CSI.5		:= LINKSRC = attributes.5
MT-Level.5	:= LINKSRC = attributes.5
architecture.5	:= LINKSRC = attributes.5
availability.5	:= LINKSRC = attributes.5
stability.5	:= LINKSRC = attributes.5
standard.5	:= LINKSRC = attributes.5

endian.5	:= LINKSRC = byteorder.5

RBAC.5		:= LINKSRC = rbac.5

advance.5	:= LINKSRC = regexp.5
compile.5	:= LINKSRC = regexp.5
step.5		:= LINKSRC = regexp.5

ANSI.5		:= LINKSRC = standards.5
C++.5		:= LINKSRC = standards.5
C.5		:= LINKSRC = standards.5
ISO.5		:= LINKSRC = standards.5
POSIX.1.5	:= LINKSRC = standards.5
POSIX.2.5	:= LINKSRC = standards.5
POSIX.5		:= LINKSRC = standards.5
SUS.5		:= LINKSRC = standards.5
SUSv2.5		:= LINKSRC = standards.5
SUSv3.5		:= LINKSRC = standards.5
SVID.5		:= LINKSRC = standards.5
SVID3.5		:= LINKSRC = standards.5
XNS.5		:= LINKSRC = standards.5
XNS4.5		:= LINKSRC = standards.5
XNS5.5		:= LINKSRC = standards.5
XPG.5		:= LINKSRC = standards.5
XPG3.5		:= LINKSRC = standards.5
XPG4.5		:= LINKSRC = standards.5
XPG4v2.5	:= LINKSRC = standards.5

teclarc.5	:= LINKSRC = tecla.5

pthreads.5	:= LINKSRC = threads.5

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
