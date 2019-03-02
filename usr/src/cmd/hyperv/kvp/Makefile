#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2017 by Delphix. All rights reserved.
#

MANIFEST=	kvp.xml
PROG=		hv_kvp_daemon

SRCS= $(PROG).c
OBJS= $(PROG).o

include ../../Makefile.cmd
include ../../Makefile.ctf

ROOTMANIFESTDIR=	$(ROOTSVCSYSTEM)/hyperv
ROOTCMDDIR=		$(ROOTLIBHYPERV)
ROOTCMD=		$(ROOTCMDDIR)/$(PROG)

LDLIBS += -lumem -lsocket -lnsl -ldlpi -lgen

HYPERV_LIB= ../../../uts/intel/io/hyperv

INCS += -I$(HYPERV_LIB) -I$(HYPERV_LIB)/utilities

CSTD=   $(CSTD_GNU99)

CPPFLAGS += $(CCVERBOSE) $(INCS)
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

CERRWARN += -_gcc=-Wno-uninitialized

# lint complains about unused _umem_* functions
LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2
LINTFLAGS64 += -xerroff=E_NAME_DEF_NOT_USED2

.KEEP_STATE:

all: $(PROG)

install: all .WAIT $(ROOTCMD) $(ROOTMANIFEST)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

check:	$(CHKMANIFEST)

lint:   lint_SRCS

include ../../Makefile.targ
