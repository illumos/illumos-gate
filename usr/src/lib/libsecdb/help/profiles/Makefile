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
# lib/libsecdb/help/profiles/Makefile
#

include ../../../../Makefile.master

HTMLENTS = \
	RtAll.html \
	RtAuditCtrl.html \
	RtAuditReview.html \
	RtContractObserver.html \
	RtConsUser.html \
	RtCronMngmnt.html \
	RtCryptoMngmnt.html \
	RtLogMngmnt.html \
	RtDeviceMngmnt.html \
	RtDeviceSecurity.html \
	RtDHCPMngmnt.html \
	RtFileSysMngmnt.html \
	RtFileSysSecurity.html \
	RtFTPMngmnt.html \
	RtInetdMngmnt.html \
	RtIPFilterMngmnt.html \
	RtKerberosClntMngmnt.html \
	RtKerberosSrvrMngmnt.html \
	RtMailMngmnt.html \
	RtMaintAndRepair.html \
	RtMediaBkup.html \
	RtMediaRestore.html \
	RtNDMPMngmnt.html \
	RtNameServiceAdmin.html \
	RtNameServiceSecure.html \
	RtNetIPsec.html \
	RtNetMngmnt.html \
	RtNetSecure.html \
	RtNetWifiMngmnt.html \
	RtNetWifiSecure.html \
	RtNetLinkSecure.html \
	RtObAccessMngmnt.html \
	RtPrntAdmin.html \
	RtProcManagement.html \
	RtRightsDelegate.html \
	RtSMBMngmnt.html \
	RtSMBFSMngmnt.html \
	RtSoftwareInstall.html \
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
	RtSysPowerMgmtBrightness.html


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
