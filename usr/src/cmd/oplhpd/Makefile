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
# cmd/oplhpd/Makefile
#

PROG =          oplhpd
PLATFORM =      SUNW,SPARC-Enterprise
MANIFEST =      oplhpd.xml
SVCMETHOD =     svc-oplhpd

include ../Makefile.cmd
include ../Makefile.cmd.64
include ../../Makefile.psm

SRCS = oplhpd.c scf_notify.c
OBJS = $(SRCS:%.c=%.o)
LINTFILES = $(SRCS:%.c=%.ln)

ROOTMANIFESTDIR = $(ROOTSVCPLATFORMSUN4U)

CPPFLAGS += -I$(SRC)/uts/sun4u/opl
LDLIBS64 += -lsysevent -lnvpair -lcfgadm -ldevinfo

CERRWARN += -_gcc=-Wno-unused-variable

PSMPROG = $(USR_PSM_LIB64_DIR)/$(PROG)

$(PSMPROG) :=	FILEMODE = 0755

.KEEP_STATE:

all: $(PROG)

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(PSMPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

$(USR_PLAT_DIR):
	-$(INS.dir)

$(USR_PSM_DIR):	$(USR_PLAT_DIR)
	-$(INS.dir)

$(USR_PSM_LIB_DIR):	$(USR_PSM_DIR)
	-$(INS.dir)

$(USR_PSM_LIB64_DIR):	$(USR_PSM_LIB_DIR)
	-$(INS.dir)

$(USR_PSM_LIB64_DIR)/%: % $(USR_PSM_LIB64_DIR)
	$(INS.file)

include ../Makefile.targ
