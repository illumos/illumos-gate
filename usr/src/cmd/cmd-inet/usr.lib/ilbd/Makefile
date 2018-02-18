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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

ILBD=		ilbd
PROG=		$(ILBD)
MANIFEST=	ilbd.xml

ILBD_OBJS=	ilbd_main.o ilbd_support.o ilbd_sg.o ilbd_rules.o ilbd_hc.o \
		ilbd_nat.o ilbd_scf.o
ILBD_SRCS=	$(ILBD_OBJS:%.o=%.c)
HDRS=		ilbd.h

LIB_INC=	$(SRC)/lib/libilb/common

OBJS=		$(ILBD_OBJS)
SRCS=		$(ILBD_SRCS)

ILBSUBDIRS=	ilb

include		../../../Makefile.cmd
include		../../../Makefile.ctf
include		../../Makefile.cmd-inet

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)/loadbalancer

CHECKHDRS=	$(HDRS:%.h=%.check)

CPPFLAGS +=	-D_FILE_OFFSET_BITS=64 -I$(CMDINETCOMMONDIR) -D_REENTRANT
CPPFLAGS +=	-I$(LIB_INC)
CPPFLAGS +=	-I$(SRC)/uts/common

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-unused-label

CSTD =      $(CSTD_GNU99)

# I18n
POFILE =        $(ILBD).po
POFILES =       $(ILBD_SRCS:%.c=%.po)

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint


LDLIBS +=	-lcmdutils -lsocket -lsecdb -lnsl -lilb -lscf -linetutil -lbsm

.KEEP_STATE:

all:		$(PROG)

$(ILBD): 	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS) $(CTFMERGE_HOOK)
		$(POST_PROCESS)

include ../Makefile.lib

install:	all $(ROOTLIBINETPROG) $(ETCILBDFILES) $(ROOTMANIFEST)

check:	$(CHKMANIFEST) $(CHECKHDRS)

clean:
	$(RM) $(OBJS)

lint:
	$(LINT.c) $(ILBD_SRCS) $(LDLIBS)

$(POFILE):	$(POFILES)
		$(RM) $@
		$(CAT) $(POFILES) > $@

all install clean clobber lint: $(ILBSUBDIRS)

include		../../../Makefile.targ

$(ILBSUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
