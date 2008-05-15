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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libsecdb/help/auths/Makefile
#

include ../../../../Makefile.master

HTMLENTS = \
	AuditConfig.html \
	AuditHeader.html \
	AuditRead.html \
	DevAllocHeader.html \
	DevAllocate.html \
	DevConfig.html \
	DevCDRW.html \
	DevGrant.html \
	DevRevoke.html \
	JobHeader.html \
	AuthJobsAdmin.html \
	JobsGrant.html \
	AuthJobsUser.html \
	LoginEnable.html \
	LoginHeader.html \
	LoginRemote.html \
	MailHeader.html \
	MailQueue.html \
	PriAdmin.html \
	AuthProfmgrAssign.html \
	AuthProfmgrDelegate.html \
	AuthProfmgrExecattrWrite.html \
	AuthProfmgrRead.html \
	ProfmgrHeader.html \
	AuthProfmgrWrite.html \
	AuthRoleAssign.html \
	AuthRoleDelegate.html \
	RoleHeader.html \
	AuthRoleWrite.html \
	SysDate.html \
	SysHeader.html \
	SysShutdown.html \
	AllSolAuthsHeader.html \
	DhcpmgrHeader.html \
	DhcpmgrWrite.html \
	BindStates.html \
	SmfAutofsStates.html \
	SmfCronStates.html \
	SmfHeader.html \
	SmfInetdStates.html \
	SmfIPsecStates.html \
	SmfManageHeader.html \
	SmfMDNSStates.html \
	SmfModifyAppl.html \
	SmfModifyDepend.html \
	SmfModifyFramework.html \
	SmfModifyHeader.html \
	SmfModifyMethod.html \
	SmfNscdStates.html \
	SmfNADDStates.html \
	SmfNDMPStates.html \
	SmfNWAMStates.html \
	SmfPowerStates.html \
	SmfRoutingStates.html \
	SmfSendmailStates.html \
	SmfSshStates.html \
	SmfSyslogStates.html \
	SmfValueHeader.html \
	SmfValueInetd.html \
	SmfValueIPsec.html \
	SmfValueIscsitgt.html \
	SmfValueMDNS.html \
	SmfValueNADD.html \
	SmfValueNDMP.html \
	AuthReadNDMP.html \
	SmfValueNWAM.html \
	SmfValueRouting.html \
	SmfValueSMB.html \
	AuthReadSMB.html \
	SmfSMBFSStates.html \
	SmfSMBStates.html \
	SmfValueVscan.html \
	SmfVscanStates.html \
	SmfWpaStates.html \
	NetworkHeader.html \
	WifiConfig.html \
	WifiWep.html \
	LinkSecurity.html \
	IdmapRules.html \
	SmfIdmapStates.html \
	SmfValueIdmap.html \
	FileChown.html \
	FileHeader.html \
	FileOwner.html \
	LabelFileDowngrade.html \
	LabelFileUpgrade.html \
	LabelHeader.html \
	LabelPrint.html \
	LabelRange.html \
	LabelServer.html \
	LabelWinDowngrade.html \
	LabelWinNoView.html \
	LabelWinUpgrade.html \
	PrintAdmin.html \
	PrintCancel.html \
	PrintHeader.html \
	PrintList.html \
	PrintNoBanner.html \
	PrintPs.html \
	PrintUnlabeled.html \
	TNDaemon.html \
	TNctl.html \
	ValueTND.html \
	SysPowerMgmtHeader.html \
	SysPowerMgmtSuspend.html \
	SysPowerMgmtSuspendtoDisk.html \
	SysPowerMgmtSuspendtoRAM.html \
	SysPowerMgmtBrightness.html \
	SysCpuPowerMgmt.html

HELPDIR=$(ROOT)/usr/lib/help
AUTHDIR=$(HELPDIR)/auths
LOCALEDIR=$(AUTHDIR)/locale
CDIR=$(LOCALEDIR)/C
DIRS=$(HELPDIR) $(AUTHDIR) $(LOCALEDIR) $(CDIR)
HELPFILES=$(HTMLENTS:%=$(CDIR)/%)

MSGDIR=		$(LOCALEDIR)
MSGDIRS =       $(HELPDIR) $(AUTHDIR) $(LOCALEDIR)

MSGFILES=	$(HTMLENTS)
MSGS=		$(MSGFILES:%=$(MSGDIR)/%)

FILEMODE= 0444
$(HELPFILES) := OWNER = root
$(HELPFILES) := GROUP = bin

.KEEP_STATE:

all:	$(HTMLENTS)

install:	all $(DIRS) $(HELPFILES)

_msg: $(MSGDIRS) $(MSGS)

$(CDIR)/%: %
	$(INS.file)

$(DIRS):
	$(INS.dir)

$(MSGDIR)/%: %
	$(INS.file)

clean clobber lint:
