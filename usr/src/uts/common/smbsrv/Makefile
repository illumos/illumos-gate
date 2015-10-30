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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
#

include ../../../Makefile.master

HDRS=	alloc.h			\
	cp_unicode.h		\
	cp_usascii.h		\
	hash_table.h		\
	mac_cifs.h		\
	mailslot.h		\
	mbuf.h			\
	msgbuf.h		\
	ndr.h			\
	netbios.h		\
	netrauth.h		\
	nmpipes.h		\
	ntaccess.h		\
	ntifs.h			\
	ntlocale.h		\
	smb_sid.h		\
	smb.h			\
	smb_door.h		\
	smb_dfs.h		\
	smb_fsops.h		\
	smb_idmap.h		\
	smb_inet.h		\
	smb_ioctl.h		\
	smb_kproto.h		\
	smb_kstat.h		\
	smb_ktypes.h		\
	smb_privilege.h		\
	smb_share.h		\
	smb_signing.h		\
	smb_token.h		\
	smb_vops.h		\
	smb_xdr.h		\
	smbinfo.h		\
	string.h		\
	svrapi.h		\
	winioctl.h		\
	winsvc.h		\
	wintypes.h

NDLHDRS= dssetup.ndl		\
	eventlog.ndl		\
	llsrpc.ndl		\
	lsarpc.ndl		\
	msgsvc.ndl		\
	ndrtypes.ndl		\
	netdfs.ndl		\
	netlogon.ndl		\
	rpcpdu.ndl		\
	samrpc.ndl		\
	security.ndl		\
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
