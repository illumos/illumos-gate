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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"@(#)Makefile	1.6	08/08/07 SMI"

include ../../../Makefile.master

HDRS=	alloc.h			\
	cifs.h			\
	codepage.h		\
	cp_cyrillic.h		\
	cp_latin1.h		\
	cp_latin2.h		\
	cp_latin3.h		\
	cp_latin4.h		\
	cp_latin5.h		\
	cp_latin6.h		\
	cp_unicode.h		\
	cp_usascii.h		\
	ctype.h			\
	doserror.h		\
	hash_table.h		\
	lm.h			\
	lmdfs.h			\
	lmerr.h			\
	lsalib.h		\
	mac_cifs.h		\
	mailslot.h		\
	mbuf.h			\
	mlrpc.h			\
	mlsvc.h			\
	mlsvc_util.h		\
	msgbuf.h		\
	ndr.h			\
	netbios.h		\
	netrauth.h		\
	nmpipes.h		\
	ntaccess.h		\
	nterror.h		\
	ntifs.h			\
	ntlocale.h		\
	smb_sid.h		\
	ntstatus.h		\
	oem.h			\
	samlib.h		\
	smb.h			\
	smb_common_door.h	\
	smb_door_svc.h		\
	smb_fsops.h		\
	smb_i18n.h		\
	smb_idmap.h		\
	smb_incl.h		\
	smb_ioctl.h		\
	smb_kproto.h		\
	smb_kstat.h		\
	smb_ktypes.h		\
	smb_privilege.h		\
	smb_share.h		\
	smb_token.h		\
	smb_vops.h		\
	smb_xdr.h		\
	smbfmt.h		\
	smbinfo.h		\
	smbtrans.h		\
	string.h		\
	svrapi.h		\
	winioctl.h		\
	winsvc.h		\
	wintypes.h

NDLHDRS= dssetup.ndl		\
	eventlog.ndl		\
	llsrpc.ndl		\
	lsarpc.ndl		\
	ndrtypes.ndl		\
	netdfs.ndl		\
	netlogon.ndl		\
	rpcpdu.ndl		\
	samrpc.ndl		\
	spoolss.ndl		\
	srvsvc.ndl		\
	svcctl.ndl		\
	winreg.ndl		\

ROOTDIR= $(ROOT)/usr/include/smbsrv
NDLDIR= $(ROOTDIR)/ndl
ROOTHDRS= $(HDRS:%=$(ROOTDIR)/%) $(NDLHDRS:%=$(ROOTDIR)/ndl/%)
CHECKHDRS= $(HDRS:%.h=%.check)

$(ROOTDIR)/%: %
	$(INS.file)

$(NDLDIR)/%: ndl/%
	$(INS.file)

$(ROOTDIR) $(NDLDIR):
	$(INS.dir)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS)

install_h: $(ROOTDIR) $(NDLDIR) $(ROOTHDRS)

check: $(CHECKHDRS)
