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
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT= 	3stmf

MANFILES=	stmfAddToHostGroup.3stmf		\
	 	stmfAddToTargetGroup.3stmf		\
	 	stmfAddViewEntry.3stmf			\
	 	stmfClearProviderData.3stmf		\
	 	stmfCreateHostGroup.3stmf		\
	 	stmfCreateLu.3stmf			\
	 	stmfCreateLuResource.3stmf		\
	 	stmfCreateTargetGroup.3stmf		\
	 	stmfDeleteHostGroup.3stmf		\
	 	stmfDeleteLu.3stmf			\
	 	stmfDeleteTargetGroup.3stmf		\
	 	stmfDevidFromIscsiName.3stmf		\
	 	stmfDevidFromWwn.3stmf			\
	 	stmfFreeLuResource.3stmf		\
	 	stmfFreeMemory.3stmf			\
	 	stmfGetHostGroupList.3stmf		\
	 	stmfGetHostGroupMembers.3stmf		\
	 	stmfGetLogicalUnitList.3stmf		\
	 	stmfGetLogicalUnitProperties.3stmf	\
	 	stmfGetLuResource.3stmf			\
	 	stmfGetPersistMethod.3stmf		\
	 	stmfGetProviderData.3stmf		\
	 	stmfGetProviderDataProt.3stmf		\
	 	stmfGetState.3stmf			\
	 	stmfGetTargetGroupList.3stmf		\
	 	stmfGetTargetGroupMembers.3stmf		\
	 	stmfGetTargetList.3stmf			\
	 	stmfGetTargetProperties.3stmf		\
	 	stmfGetViewEntryList.3stmf		\
	 	stmfModifyLu.3stmf			\
	 	stmfOfflineLogicalUnit.3stmf		\
	 	stmfOfflineTarget.3stmf			\
	 	stmfOnlineLogicalUnit.3stmf		\
	 	stmfOnlineTarget.3stmf			\
	 	stmfRemoveFromHostGroup.3stmf		\
	 	stmfRemoveFromTargetGroup.3stmf		\
	 	stmfRemoveViewEntry.3stmf		\
	 	stmfSetLuProp.3stmf			\
	 	stmfSetPersistMethod.3stmf		\
	 	stmfSetProviderData.3stmf		\
	 	stmfSetProviderDataProt.3stmf

MANLINKS=	stmfGetLuProp.3stmf			\
		stmfModifyLuByFname.3stmf

stmfModifyLuByFname.3stmf	:= LINKSRC = stmfModifyLu.3stmf

stmfGetLuProp.3stmf		:= LINKSRC = stmfSetLuProp.3stmf

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
