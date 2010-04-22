# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.

include ../../../../Makefile.master

HTMLENTS = \
	RtAcctadm.html \
	RtAll.html \
	RtAuditCtrl.html \
	RtAuditReview.html \
	RtContractObserver.html \
	RtConsUser.html \
	RtCronMngmnt.html \
	RtCryptoMngmnt.html \
	RtExAcctFlow.html \
	RtExAcctProcess.html \
	RtExAcctTask.html \
	RtExAcctNet.html \
	RtLogMngmnt.html \
	RtDeviceMngmnt.html \
	RtDeviceSecurity.html \
	RtDHCPMngmnt.html \
	RtFileSysMngmnt.html \
	RtFileSysSecurity.html \
	RtFTPMngmnt.html \
	RtHotplugMngmnt.html \
	RtInetdMngmnt.html \
	RtIPFilterMngmnt.html \
	RtKerberosClntMngmnt.html \
	RtKerberosSrvrMngmnt.html \
	RtMailMngmnt.html \
	RtMaintAndRepair.html \
	RtMediaBkup.html \
	RtMediaCtlg.html \
	RtMediaRestore.html \
	RtNDMPMngmnt.html \
	RtNameServiceAdmin.html \
	RtNameServiceSecure.html \
	RtNetAutoconfAdmin.html \
	RtNetAutoconfUser.html \
	RtNetILB.html \
	RtNetIPsec.html \
	RtNetMngmnt.html \
	RtNetObservability.html \
	RtNetSecure.html \
	RtNetWifiMngmnt.html \
	RtNetWifiSecure.html \
	RtNetLinkSecure.html \
	RtNetVRRP.html \
	RtObAccessMngmnt.html \
	RtOperator.html \
	RtPriAdmin.html \
	RtPrntAdmin.html \
	RtProcManagement.html \
	RtReparseMngmnt.html \
	RtRightsDelegate.html \
	RtSMBMngmnt.html \
	RtSMBFSMngmnt.html \
	RtSoftwareInstall.html \
	RtSysAdmin.html \
	RtSysEvMngmnt.html \
	RtUserMngmnt.html \
	RtUserSecurity.html \
	RtDatAdmin.html \
	RtZFSFileSysMngmnt.html \
	RtZFSStorageMngmnt.html \
	RtZoneMngmnt.html \
	RtInfoSec.html \
	RtObjectLabelMngmnt.html \
	RtOutsideAccred.html \
	RtDefault.html \
	RtIdmapMngmnt.html \
	RtIdmapNameRulesMngmnt.html \
	RtVscanMngmnt.html \
	RtSysPowerMgmt.html \
	RtSysPowerMgmtSuspend.html \
	RtSysPowerMgmtSuspendtoDisk.html \
	RtSysPowerMgmtSuspendtoRAM.html \
	RtSysPowerMgmtBrightness.html \
	RtCPUPowerManagement.html

HELPDIR =	$(ROOT)/usr/lib/help
PROFDIR =	$(HELPDIR)/profiles
LOCALEDIR =	$(PROFDIR)/locale
CDIR =		$(LOCALEDIR)/C
DIRS =		$(HELPDIR) $(PROFDIR) $(LOCALEDIR) $(CDIR)
HELPFILES=$(HTMLENTS:%=$(CDIR)/%)

MSGDIR=		$(LOCALEDIR)
MSGDIRS =       $(HELPDIR) $(PROFDIR) $(LOCALEDIR)

MSGFILES=	$(HTMLENTS)
MSGS=		$(MSGFILES:%=$(MSGDIR)/%)

FILEMODE = 0444

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
