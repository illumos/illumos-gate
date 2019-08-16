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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY= fp.a
VERS= .1

OBJECTS = cfga_fp.o cfga_rcm.o cfga_cs.o cfga_utils.o
OBJECTS += cfga_cvt.o cfga_list.o cfga_rep.o

# include library definitions
include ../../../Makefile.lib

SRCDIR =	../common
ROOTLIBDIR=	$(ROOT)/usr/lib/cfgadm
ROOTLIBDIR64=	$(ROOTLIBDIR)/$(MACH64)

LIBS=	$(DYNLIB)

LINTFLAGS +=	-DDEBUG
LINTFLAGS64 +=	-DDEBUG

CFLAGS +=	$(CCVERBOSE)
CFLAGS64 +=	$(CCVERBOSE)

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-char-subscripts
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-address

# not linted
SMATCH=off

CPPFLAGS += -D_POSIX_PTHREAD_SEMANTICS

LINTFLAGS += -erroff=E_SEC_SPRINTF_UNBOUNDED_COPY
LINTFLAGS += -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTFLAGS += -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTFLAGS += -erroff=E_BAD_FORMAT_ARG_TYPE2
LINTFLAGS += -erroff=E_SEC_CREAT_WITHOUT_MODE
LINTFLAGS64 += $(LINTFLAGS)

LDLIBS +=	-lc -ldevice -ldevinfo -lrcm
LDLIBS +=	-lHBAAPI -lgen

MANIFEST=	devices-fc-fabric.xml
ROOTMANIFESTDIR=	$(ROOT)/lib/svc/manifest/system/device
ROOTMANIFEST=	$(MANIFEST:%=$(ROOTMANIFESTDIR)/%)
$(ROOTMANIFEST)	:= FILEMODE= 444

SVCMETHOD=	fc-fabric
ROOTSVCMETHODDIR=	$(ROOT)/lib/svc/method
ROOTSVCMETHOD=	$(SVCMETHOD:%=$(ROOTSVCMETHODDIR)/%)
$(ROOTSVCMETHOD):= FILEMODE= 555

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

# Install rules

$(ROOTLIBDIR)/%: % $(ROOTLIBDIR)
	$(INS.file)

$(ROOTLIBDIR64)/%: % $(ROOTLIBDIR64)
	$(INS.file)

$(ROOTLIBDIR) $(ROOTLIBDIR64):
	$(INS.dir)

$(ROOTMANIFESTDIR)/%: ../common/% $(ROOTMANIFESTDIR)
	$(INS.file)

$(ROOTSVCMETHODDIR)/%: ../common/% $(ROOTSVCMETHODDIR)
	$(INS.file)

$(ROOTSVCMETHODDIR) $(ROOTMANIFESTDIR):
	$(INS.dir)

# include library targets
include ../../../Makefile.targ

objs/%.o pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
