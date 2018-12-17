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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY=	libmpscsi_vhci.a
VERS=		.1
OBJECTS=	Initialize.o MP_AssignLogicalUnitToTPG.o \
		MP_CancelOverridePath.o MP_DeregForObjPropChangesPlugin.o \
		MP_DeregForObjVisChangesPlugin.o MP_DisableAutoFailbackLu.o \
		MP_DisableAutoFailbackPlugin.o MP_DisableAutoProbingLu.o \
		MP_DisableAutoProbingPlugin.o MP_DisablePath.o \
		MP_EnableAutoFailbackLu.o MP_EnableAutoFailbackPlugin.o \
		MP_EnableAutoProbingLu.o MP_EnableAutoProbingPlugin.o \
		MP_EnablePath.o MP_GetAssociatedPathOidList.o \
		MP_GetAssociatedTPGOidList.o \
		MP_GetDeviceProductOidListPlugin.o \
		MP_GetDeviceProductProperties.o \
		MP_GetInitiatorPortOidListPlugin.o \
		MP_GetInitiatorPortProperties.o \
		MP_GetMPLogicalUnitProperties.o \
		MP_GetMPLuOidListFromTPG.o MP_GetMultipathLusDevProd.o \
		MP_GetMultipathLusPlugin.o MP_GetPathLogicalUnitProperties.o \
		MP_GetPluginPropertiesPlugin.o \
		MP_GetProprietaryLBOidListPlugin.o MP_GetProprietaryLBProp.o \
		MP_GetTargetPortGroupProperties.o MP_GetTargetPortOidList.o \
		MP_GetTargetPortProperties.o MP_RegForObjPropChangesPlugin.o \
		MP_RegForObjVisChangesPlugin.o MP_SetFailbackPollingRateLu.o \
		MP_SetFailbackPollingRatePlugin.o \
		MP_SetLogicalUnitLoadBalanceType.o MP_SetOverridePath.o \
		MP_SetPathWeight.o MP_SetPluginLBTypePlugin.o \
		MP_SetProbingPollingRateLu.o MP_SetProbingPollingRatePlugin.o \
		MP_SetProprietaryProperties.o MP_SetTPGAccess.o \
		Sun_MP_SendScsiCmd.o Terminate.o debug_logging.o mp_utils.o

include ../../../Makefile.lib
include ../../../Makefile.rootfs

SRCDIR = 	../common

LIBS =		$(DYNLIB)
LDLIBS +=	-lc -ldevinfo -lsysevent -lnvpair

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR) -D_POSIX_PTHREAD_SEMANTICS
CPPFLAGS +=	-DBUILD_TIME='"Wed Sep 24 12:00:00 2008"'

# not linted
SMATCH=off

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../../Makefile.targ
