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
#
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

PROG=		ldmad
MANIFEST=	ldoms-agents.xml
SVCMETHOD=	ldoms-agents

include ../Makefile.cmd


LOCAL_SRCS=	ldmad.c			\
		ldma_log.c		\
		ldma_device.c		\
		ldma_system.c		\
		ldma_dio.c		\
		mdesc_lib.c

LOCAL_OBJS=	$(LOCAL_SRCS:%.c=%.o)

COMMONBASE = ../../common

COMMON_SRCS =	mdesc_findname.c	\
		mdesc_findnodeprop.c	\
		mdesc_fini.c		\
		mdesc_getpropval.c	\
		mdesc_getpropstr.c	\
		mdesc_init_intern.c	\
		mdesc_nodecount.c	\
		mdesc_rootnode.c	\
		mdesc_scandag.c

COMMON_OBJS =	$(COMMON_SRCS:%.c=%.o)

OBJS = $(LOCAL_OBJS) $(COMMON_OBJS)
SRCS = $(LOCAL_SRCS) $(COMMON_SRCS:%.c=$(COMMONBASE)/mdesc/%.c)

ROOTCMDDIR=		$(ROOTLIB)/ldoms
ROOTMANIFESTDIR=	$(ROOTSVCPLATFORMSUN4V)
$(ROOTMANIFEST)		:= FILEMODE= 444

LDLIBS +=	-lds -ldladm -ldevinfo -lpri
INCS +=		-I$(ROOT)/usr/platform/sun4v/include/sys
INCS +=		-I$(SRC)/uts/sun4v
CPPFLAGS += 	-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 $(INCS)
CSTD =	$(CSTD_GNU99)
CERRWARN +=	-_gcc=-Wno-uninitialized

LINTFLAGS += -erroff=E_BAD_PTR_CAST_ALIGN

.KEEP_STATE:

all: $(PROG) 

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTCMD) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check: $(CHKMANIFEST)

lint: lint_SRCS

clean:
	$(RM) $(PROG) $(OBJS) $(LINT_FILES)

include ../Makefile.targ

%.o: $(COMMONBASE)/mdesc/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

