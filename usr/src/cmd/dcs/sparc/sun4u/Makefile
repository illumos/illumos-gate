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
# Makefile definitions for Domain Configuration Server (DCS)
#

MANIFEST=	dcs.xml

include ../../../Makefile.cmd
include ../../../../Makefile.psm

PROG=		dcs

CLASS=		32

PLATFORM=	sun4u

SVCMETHOD=	svc-$(PROG)

#
# Set CONCURR_MODE to one of the following:
#
#	MULTI_THR  - multiple threads with _no_ i18n support*
#	MULTI_PROC - multiple processes with i18n support
#
# * Currently, there is no per thread locale support in Solaris.
#   Thus, multiple processes is the only way to fully support i18n.
#
CONCURR_MODE=	MULTI_PROC

SRCS=		dcs.c \
		dcs_ses.c \
		dcs_msg.c \
		rdr_messages.c \
		rsrc_info.c \
		ri_init.c

HDRS=		dcs.h \
		rdr_messages.h \
		rdr_param_types.h \
		remote_cfg.h \
		rsrc_info.h \
		rsrc_info_impl.h \
		$(USR_PSM_ISYS_DIR)/sbd_ioctl.h

OBJS=		$(SRCS:%.c=%.o)

LINT_SRCS=	$(SRCS)
LINT_FILES=	$(LINT_SRCS:%.c=%.ln)

POFILES=	dcs_msg.po

$(ROOTLIBPROG) :=	FILEMODE=	0755

ROOTMANIFESTDIR=	$(ROOTSVCPLATFORMSUN4U)

#
# FLAGS:
#
MULTI_THR_FLAGS=	-D_REENTRANT -DDCS_MULTI_THREAD

MULTI_PROC_FLAGS=	-D__EXTENSIONS__

CPPFLAGS= 	-I$(USR_PSM_INCL_DIR) $(CPPFLAGS.master) \
		$($(CONCURR_MODE)_FLAGS)

LINT_FLAGS=	-c -Nlevel=4 -Ncheck $($(CONCURR_MODE)_FLAGS)

XGETFLAGS +=	-a -s -x $(PROG).xcl

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized

#
# LIBRARIES:
#
MULTI_THR_LIBS=		-D_REENTRANT

MULTI_PROC_LIBS=

LDLIBS +=	$($(CONCURR_MODE)_LIBS) \
		-lsocket \
		-lcfgadm \
		-ldevinfo \
		-lrcm \
		-lnvpair \
		-lkstat

.KEEP_STATE:


all: $(PROG)

$(PROG): $(OBJS) $(HDRS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTLIBPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

lint:
	$(LINT) $(LINT_FLAGS) $(CPPFLAGS) $(LINT_SRCS)

clean:
	$(RM) $(PROG) $(OBJS) $(LINT_FILES)

$(POFILE): $(POFILES)
	$(RM) $(POFILE)
	cat $(POFILES) > $(POFILE)

include ../../../Makefile.targ
include ../../../../Makefile.psm.targ
