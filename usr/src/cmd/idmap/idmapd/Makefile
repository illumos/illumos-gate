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
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
#

PROG =		idmapd
MANIFEST =	idmap.xml
SERVEROBJS =				\
	adspriv_impl.o			\
	directory_provider_builtin.o	\
	directory_provider_nsswitch.o	\
	directory_provider_ad.o		\
	directory_server.o		\
	adutils.o			\
	dbutils.o			\
	idmap_config.o			\
	idmapd.o			\
	init.o				\
	idmap_lsa.o			\
	krb5_lookup.o			\
	nldaputils.o			\
	server.o			\
	wksids.o

GENOBJS =				\
	adspriv_srv.o			\
	rpc_svc.o

SERVERSRCS =	$(SERVEROBJS:%.o=%.c)
GENSRCS = 	$(GENOBJS:%.o=%.c)
OBJS =		$(SERVEROBJS) $(GENOBJS)
SRCS =		$(SERVERSRCS)
POFILES =	$(OBJS:%.o=%.po)

all :=		TARGET = all
install :=	TARGET = install
clean :=	TARGET = clean
clobber :=	TARGET = clobber

include ../../Makefile.cmd

CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-uninitialized

TEXT_DOMAIN =	SUNW_OST_OSLIB
XGETTEXT =	$(GNUXGETTEXT)
XGETFLAGS =	--foreign-user --strict -n -E --width=72 \
		--omit-header --keyword=directoryError:2 \
		--language=C --force-po

CSTD = $(CSTD_GNU99)
POFILE =	$(PROG)_all.po

RPC_MSGOUT_OPT = -DRPC_MSGOUT=idmap_rpc_msgout

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)
$(ROOTMANIFEST) := FILEMODE= 444
RPCSVC= ../../../uts/common/rpcsvc
ADS_CMN=../../../lib/libads/common

INCS += -I. -I../../../lib/libidmap/common \
	 -I../../../lib/libsldap/common \
	 -I../../../lib/libadutils/common \
	 -I $(ADS_CMN) \
	 -I../../../lib/smbsrv/libsmb/common

# Should not have to do this, but the Kerberos includes are a mess.
INCS += -I $(ROOT)/usr/include/kerberosv5

$(OBJS) := CPPFLAGS += $(INCS) -D_REENTRANT
$(POFILE) := CPPFLAGS += $(INCS)

LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2
LINTFLAGS += -xerroff=E_NAME_USED_NOT_DEF2

CFLAGS += $(CCVERBOSE)
LDLIBS += \
	-lsqlite-sys \
	-lsecdb \
	-lsocket \
	-lnsl \
	-lidmap \
	-lscf \
	-lsldap \
	-lldap \
	-luuid \
	-ladutils \
	-lads \
	-lumem \
	-lnvpair \
	-luutil \
	-L $(ROOT)/usr/lib/smbsrv \
	-lsmb

rpc_svc.o := CFLAGS += $(RPC_MSGOUT_OPT)

$(PROG) := MAPFILES = $(MAPFILE.INT) $(MAPFILE.NGB)
$(PROG) := LDFLAGS += $(MAPFILES:%=-M%) \
	-R /usr/lib/smbsrv

DIRMODE = 0755
FILEMODE = 0555

lint_SRCS := CPPFLAGS += $(INCS) -D_REENTRANT $(RPC_MSGOUT_OPT)

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG)

$(PROG): $(OBJS) $$(MAPFILES)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $(POFILE)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTLIBPROG) $(ROOTMANIFEST)

check: $(CHKMANIFEST)

clean:
	$(RM) $(OBJS) $(GENSRCS)

lint:   lint_SRCS

lint_SRCS:

RPCGENFLAGS = -CMN

adspriv_srv.o : adspriv_srv.c

adspriv_srv.c: 
	$(RPCGEN) $(RPCGENFLAGS) -m $(ADS_CMN)/ads_priv.x > $@

rpc_svc.o : rpc_svc.c

rpc_svc.c : $(RPCSVC)/idmap_prot.x
	$(RPCGEN) $(RPCGENFLAGS) -m $(RPCSVC)/idmap_prot.x > $@

include ../../Makefile.targ
