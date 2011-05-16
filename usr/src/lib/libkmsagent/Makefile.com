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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

LIBRARY= libkmsagent.a
VERS= .1

LIB_C_OBJECTS= \
	SYSCommon.o \
	ieee80211_crypto.o \
	k_setupssl.o

LIB_CPP_OBJECTS= \
	KMSAgent.o \
	KMSAgentChallenge.o \
	KMSAgentCryptoUtilities.o \
	KMSAgentDataUnitCache.o \
	KMSAgentFatalState.o \
	KMSAgentKeyCallout.o \
	KMSAgentKnownAnswerTests.o \
	KMSAgentLoadBalancer.o \
	KMSAgentPKICert.o \
	KMSAgentPKICertOpenSSL.o \
	KMSAgentPKICommon.o \
	KMSAgentPKIKey.o \
	KMSAgentPKIKeyOpenSSL.o \
	KMSAgentSoapUtilities.o \
	KMSAgentStorage.o \
	KMSAgentStringUtilities.o \
	KMSAuditLogger.o \
	KMSClientProfile.o

SOAP_OBJECTS =\
	AgentServiceNamespace.o \
	CAServiceNamespace.o \
	CertificateServiceNamespace.o \
	DiscoveryServiceNamespace.o \
	KMS_AgentC.o \
	KMS_AgentClient.o \
	KMS_CAC.o \
	KMS_CAClient.o \
	KMS_CertificateC.o \
	KMS_CertificateClient.o \
	KMS_DiscoveryC.o \
	KMS_DiscoveryClient.o \
	envC.o \
	stdsoap2.o

OBJECTS= \
	$(LIB_C_OBJECTS) \
	$(LIB_CPP_OBJECTS)	\
	$(SOAP_OBJECTS)

LIBSRCDIR= ../common
SOAPSRCDIR= ../common/SOAP

include $(SRC)/lib/Makefile.lib

SRCDIR=../common
CSRCS 	= $(LIB_C_OBJECTS:%.o=$(LIBSRCDIR)/%.c)
LIBSRCS = $(LIB_CPP_OBJECTS:%.o=$(LIBSRCDIR)/%.cpp) $(CSRCS)
SOAPSRCS= $(SOAP_OBJECTS:%.o=$(SOAPSRCDIR)/%.cpp)

CCOBJS = $(LIB_CPP_OBJECTS:%.o=pics/%.o) \
	$(SOAP_OBJECTS:%.o=pics/%.o)

LIBS	=	$(DYNLIB)

$(__SUNC)CCNEEDED =	-lCstd -lCrun

LDLIBS  +=      $(CCNEEDED) -lpam -lc -lsoftcrypto -lcrypto -lssl -lsocket
LDLIBS64  +=    $(CCNEEDED) -lpam -lc -lsoftcrypto -lcrypto -lssl -lsocket

DEFINES =	-DKMSUSERPKCS12 -D_REENTRANT -DNOWCSICMP -DUNIX \
		-DWITH_OPENSSL -DHAVE_OPENSSL_SSL_H \
		-DWITH_IPV6 -D_POSIX_THREADS -DXML_STATIC \
		-DHAVE_EXPAT_CONFIG_H -DK_SOLARIS_PLATFORM  \
		-DOPENSSL_NO_DEPRECATED \
		-DKMS_AGENT_VERSION_STRING=\"KMSAgentLibraryVersion:Build1016\"

CFLAGS +=	$(CCVERBOSE)

#
# When building C++ objects, redefine CCFLAGS for 32-bit builds to
# use "compat=5" instead of "compat=4".
# The 64-bit CCFLAGS already use compat=5 option (see $SRC/Makefile.master)
#
$(CCOBJS) := i386_CCFLAGS = \
		-compat=5 \
		-Qoption ccfe -messages=no%anachronism \
		-Qoption ccfe -features=no%conststrings \
		$(CCERRWARN)

$(CCOBJS) := sparc_CCFLAGS = \
		-cg92 -compat=5 \
		-Qoption ccfe -messages=no%anachronism \
		-Qoption ccfe -features=no%conststrings \
		$(CCERRWARN)

CPPFLAGS +=	-I../common -I../common/SOAP -I$(SRC)/common/crypto/aes $(DEFINES)

COPTFLAG +=	-xCC
COPTFLAG64 +=	-xCC

pics/stdsoap2.o:=	CPPFLAGS   += -DWITH_NONAMESPACES

ROOTLIBDIR=     $(ROOT)/usr/lib
ROOTLIBDIR64=   $(ROOT)/usr/lib/$(MACH64)

.KEEP_STATE:

all:    $(LIBS)

#
# Don't lint C++ code
#
lint: 

#
# Need special rules here because the files are named ".cpp" instead
# of ".cc".  The source comes from KMS, and we need to keep them in sync
# so we won't change the naming convention.
#
pics/%.o:	$(LIBSRCDIR)/%.cpp
	$(COMPILE.cc) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(SOAPSRCDIR)/%.cpp
	$(COMPILE.cc) -o $@ $<
	$(POST_PROCESS_O)

.cpp:
	$(LINK.cc) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

.cpp.o:
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ

