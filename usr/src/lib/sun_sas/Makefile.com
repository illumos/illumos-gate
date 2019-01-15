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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =	libsun_sas.a
VERS =		.1

OBJECTS	=	devtree_hba_disco.o \
	      	devtree_device_disco.o \
	      	devtree_phy_disco.o \
	      	devlink_disco.o \
	      	event.o \
	      	verify.o \
	      	SMHBA_RegisterLibrary.o \
	      	Sun_sasLoadLibrary.o \
	      	Sun_sasGetNumberOfAdapters.o \
	      	Sun_sasGetTargetMapping.o \
	      	Sun_sasGetAdapterName.o \
		Sun_sasGetAdapterAttributes.o \
		Sun_sasGetAdapterPortAttributes.o \
		Sun_sasGetDiscoveredPortAttributes.o \
		Sun_sasGetPortAttributesByWWN.o \
		Sun_sasGetSASPhyAttributes.o \
		Sun_sasGetPortType.o \
	      	Sun_sasGetNumberOfPorts.o \
	      	Sun_sasGetVersion.o \
	      	Sun_sasGetPhyStatistics.o \
	      	Sun_sasGetVendorLibraryAttributes.o \
	      	Sun_sasFreeLibrary.o \
	      	Sun_sasOpenAdapter.o \
	      	Sun_sasCloseAdapter.o \
	      	Sun_sasRefreshInformation.o \
	      	Sun_sasRefreshAdapterConfiguration.o \
	      	Sun_sasGetLUNStatistics.o \
	      	Sun_sasGetProtocolStatistics.o \
	      	Sun_sasGetPersistentBinding.o \
	      	Sun_sasSetPersistentBinding.o \
		Sun_sasSendSMPPassThru.o \
		Sun_sasScsiInquiry.o \
		Sun_sasScsiReportLUNs.o \
		Sun_sasScsiReadCapacity.o \
		sun_sas.o \
		log.o 

include ../../Makefile.lib

LIBS =		$(DYNLIB)
SRCDIR=		../common

INCS +=		-I$(SRCDIR)
INCS +=		-I$(SRC)/lib/smhba/common
INCS +=		-I$(SRC)/lib/hbaapi/common
INCS +=		-I$(SRC)/lib/libdevid

CFLAGS +=	-mt
CFLAGS +=	$(CCVERBOSE)
CFLAGS64 +=	-mt
CFLAGS64 +=	$(CCVERBOSE)
CPPFLAGS +=	$(INCS) -D_POSIX_PTHREAD_SEMANTICS
CPPFLAGS +=	-DBUILD_TIME='"Wed Feb 4 12:00:00 2009"'

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-value

# not linted
SMATCH=off

LDLIBS		+= -ldevinfo
LDLIBS		+= -lsysevent
LDLIBS		+= -lnvpair
LDLIBS		+= -lc
LDLIBS		+= -lkstat
LDLIBS		+= -ldevid

$(LINTLIB) := SRCS=	$(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ
