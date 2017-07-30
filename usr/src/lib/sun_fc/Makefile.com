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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

LIBRARYCCC =	libsun_fc.a
VERS =		.1

OBJECTS	=	Lockable.o \
		HBA.o \
		HBAPort.o \
		Handle.o \
		HandlePort.o \
		IOError.o \
		InternalError.o \
		Listener.o \
		EventBridgeFactory.o \
		HBAList.o \
		FCHBA.o \
		FCHBAPort.o \
		TgtFCHBA.o \
		TgtFCHBAPort.o \
		FCSyseventBridge.o \
		AdapterAddEventListener.o \
		AdapterEventListener.o \
		AdapterPortEventListener.o \
		AdapterPortStatEventListener.o \
		LinkEventListener.o \
		TargetEventListener.o \
		HBA_RegisterLibrary.o \
		HBA_RegisterLibraryV2.o \
		Sun_fcCloseAdapter.o \
		Sun_fcFreeLibrary.o \
		Sun_fcGetAdapterAttributes.o \
		Sun_fcGetAdapterName.o \
		Sun_fcGetAdapterPortAttributes.o \
		Sun_fcGetBindingCapability.o \
		Sun_fcGetBindingSupport.o \
		Sun_fcGetDiscPortAttrs.o \
		Sun_fcGetEventBuffer.o \
		Sun_fcGetFC4Statistics.o \
		Sun_fcGetFCPStatistics.o \
		Sun_fcGetFcpPersistentBinding.o \
		Sun_fcGetFcpTargetMapping.o \
		Sun_fcGetFcpTargetMappingV2.o \
		Sun_fcGetNumberOfAdapters.o \
		Sun_fcGetPersistentBindingV2.o \
		Sun_fcGetPortAttributesByWWN.o \
		Sun_fcGetPortStatistics.o \
		Sun_fcGetRNIDMgmtInfo.o \
		Sun_fcGetVendorLibraryAttributes.o \
		Sun_fcGetVersion.o \
		Sun_fcLoadLibrary.o \
		Sun_fcOpenAdapter.o \
		Sun_fcOpenAdapterByWWN.o \
		Sun_fcRefreshAdapterConfiguration.o \
		Sun_fcRefreshInformation.o \
		Sun_fcRegisterForAdapterAddEvents.o \
		Sun_fcRegisterForAdapterEvents.o \
		Sun_fcRegisterForAdapterPortEvents.o \
		Sun_fcRegisterForAdapterPortStatEvents.o \
		Sun_fcRegisterForLinkEvents.o \
		Sun_fcRegisterForTargetEvents.o \
		Sun_fcRemoveAllPersistentBindings.o \
		Sun_fcRemoveCallback.o \
		Sun_fcRemovePersistentBinding.o \
		Sun_fcResetStatistics.o \
		Sun_fcScsiInquiryV2.o \
		Sun_fcScsiReadCapacityV2.o \
		Sun_fcScsiReportLUNsV2.o \
		Sun_fcSendCTPassThru.o \
		Sun_fcSendCTPassThruV2.o \
		Sun_fcSendLIRR.o \
		Sun_fcSendRLS.o \
		Sun_fcSendRNID.o \
		Sun_fcSendRNIDV2.o \
		Sun_fcSendRPL.o \
		Sun_fcSendRPS.o \
		Sun_fcSendReadCapacity.o \
		Sun_fcSendReportLUNs.o \
		Sun_fcSendSRL.o \
		Sun_fcSendScsiInquiry.o \
		Sun_fcSetBindingSupport.o \
		Sun_fcSetPersistentBindingV2.o \
		Sun_fcSetRNIDMgmtInfo.o \
		Sun_fcGetNumberOfTgtAdapters.o \
		Sun_fcGetTgtAdapterName.o \
		Sun_fcOpenTgtAdapter.o \
		Sun_fcOpenTgtAdapterByWWN.o \
		Trace.o \
		Sun_fcNPIVGetAdapterAttributes.o \
		Sun_fcGetPortNPIVAttributes.o \
		Sun_fcCreateNPIVPort.o \
		Sun_fcGetNPIVPortInfo.o \
		Sun_fcDeleteNPIVPort.o \
		HBANPIVPort.o \
		FCHBANPIVPort.o \
		HandleNPIVPort.o \
		AdapterDeviceEventListener.o \
		Sun_fcRegisterForAdapterDeviceEvents.o \
		Sun_fcDoForceLip.o \
		Sun_fcAdapterCreateWWN.o \
		Sun_fcAdapterReturnWWN.o

include ../../Makefile.lib

LIBS =		$(DYNLIBCCC)
SRCDIR=		../common

INCS +=		-I$(SRCDIR)
INCS +=		-I$(SRC)/lib/hbaapi/common

CCFLAGS +=	-D_POSIX_PTHREAD_SEMANTICS
CCFLAGS +=	-compat=5 -_g++=-std=c++98
CCFLAGS64 +=	-D_POSIX_PTHREAD_SEMANTICS
CCFLAGS64 +=	-compat=5 -_g++=-std=c++98
CPPFLAGS +=	$(INCS) -DBUILD_TIME='"Wed Sep 24 12:00:00 2008"'

LDLIBS			+= -ldevinfo
LDLIBS			+= -lsysevent
LDLIBS			+= -lnvpair
$(__SUNC)CCNEEDED	= $(CCEXTNEEDED)
LDLIBS			+= $(CCNEEDED)
LDLIBS			+= -lc

$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all: $(LIBS)

lint:
	@echo "This section is not required to be lint clean"
	@echo "C++"

include ../../Makefile.targ
