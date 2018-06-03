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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../../Makefile.cmd
include ../../Makefile.cmd.64

.KEEP_STATE:

PROG				= rcapd
ROOTUSRLIBRCAP			= $(ROOT)/usr/lib/rcap
ROOTUSRLIBRCAPPROG		= $(ROOTUSRLIBRCAP)/$(PROG)

COMMON_DIR=	../common

MANIFEST = rcap.xml
ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)
$(ROOTSVCSYSTEM)/rcap.xml := FILEMODE = 0444


SRCS =	rcapd_main.c \
	rcapd_collection.c \
	rcapd_collection_project.c \
	rcapd_collection_zone.c \
	rcapd_mapping.c \
	rcapd_rfd.c \
	rcapd_scanner.c \
	rcapd_stat.c \
	utils.c

LINTSRCS = rcapd_main.c \
	rcapd_collection.c \
	rcapd_collection_project.c \
	rcapd_collection_zone.c \
	rcapd_mapping.c \
	rcapd_rfd.c \
	rcapd_scanner.c \
	$(COMMON_DIR)/rcapd_stat.c \
	$(COMMON_DIR)/utils.c

$(NOT_RELEASE_BUILD)CPPFLAGS	+= -DDEBUG
CPPFLAGS			+= -DDEBUG_MSG
CPPFLAGS			+= -I$(COMMON_DIR)
LDLIBS			+= -lkstat -lproc -lproject -lzonecfg -lumem -lscf
LDLIBS			+= $(EXTRA_LDLIBS)

LINTFLAGS64		+= -u

OBJS =			$(SRCS:%.c=%.o) rcapd_conf.o

POFILES =		$(OBJS:%.o=%.po)
POFILE =		$(PROG).po

CLOBBERFILES +=		$(POFILES) $(POFILE)

include ../Makefile.com

.NO_PARALLEL:
.PARALLEL: $(OBJS)

all: $(PROG)

install: all $(ROOTUSRLIBRCAPPROG) $(ROOTUSRLIBRCAP) $(ROOTMANIFEST)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

check: $(CHKMANIFEST)

clean:
	$(RM) $(OBJS)
	$(RM) rcapd_conf.c

lint:
	$(LINT.c) $(LINTSRCS) $(LDLIBS)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(ROOTUSRLIBRCAP)/%: $(ROOTUSRLIBRCAP) %
	$(INS.file)

include ../../Makefile.targ
