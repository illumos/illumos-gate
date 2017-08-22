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

# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.

#
# lib/libsecdb/help/auths/Makefile
#

include ../../../../Makefile.master

HTMLENTS = \
	AuditHeader.html \
	DevAllocHeader.html \
	DevAllocate.html \
	DevConfig.html \
	DevCDRW.html \
	DevGrant.html \
	DevRevoke.html \
        HotplugHeader.html \
	HotplugModify.html \
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
	SysMaintenance.html \
	DhcpmgrHeader.html \
	DhcpmgrWrite.html \
	BindStates.html \
	SmfAllocate.html \
	SmfAutofsStates.html \
	SmfCoreadmStates.html \
	SmfCronStates.html \
	SmfExAcctFlowStates.html \
	SmfExAcctProcessStates.html \
	SmfExAcctTaskStates.html \
	SmfExAcctNetStates.html \
	SmfHeader.html \
	SmfILBStates.html \
	SmfInetdStates.html \
	SmfIPsecStates.html \
	SmfLocationStates.html \
	SmfManageAudit.html \
	SmfManageHeader.html \
	SmfManageHotplug.html \
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
	SmfReparseStates.html \
	SmfRoutingStates.html \
	SmfSendmailStates.html \
	SmfSshStates.html \
	SmfSyslogStates.html \
	SmfValueAudit.html \
	SmfValueCoreadm.html \
	SmfValueExAcctFlow.html \
	SmfValueExAcctProcess.html \
	SmfValueExAcctTask.html \
	SmfValueExAcctNet.html \
	SmfValueFirewall.html \
	SmfVtStates.html \
	SmfValueHeader.html \
	SmfValueInetd.html \
	SmfValueIPsec.html \
	SmfValueMDNS.html \
	SmfValueNADD.html \
	SmfValueNDMP.html \
	AuthReadNDMP.html \
	SmfValueNWAM.html \
	SmfValueProcSec.html \
	SmfValueRouting.html \
	SmfValueSMB.html \
	AuthReadSMB.html \
	SmfSMBFSStates.html \
	SmfSMBStates.html \
	SmfValueVscan.html \
	SmfVscanStates.html \
	SmfValueVt.html	\
	SmfVRRPStates.html \
	SmfWpaStates.html \
	NetworkAutoconfRead.html \
	NetworkAutoconfSelect.html \
	NetworkAutoconfWlan.html \
	NetworkAutoconfWrite.html \
	NetworkILBconf.html \
	NetworkILBenable.html \
	NetworkHeader.html \
	NetworkVRRP.html \
	NetworkInterfaceConfig.html \
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
	SysCpuPowerMgmt.html \
	SysSyseventRead.html \
	SysSyseventWrite.html \
	SmfManageZFSSnap.html \
	ZoneCloneFrom.html \
	ZoneHeader.html \
	ZoneLogin.html \
	ZoneManage.html

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
