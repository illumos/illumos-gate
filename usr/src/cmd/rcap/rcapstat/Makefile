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
# Copyright 2020 Joyent, Inc.
#

.KEEP_STATE:
.SUFFIXES:

include ../../Makefile.cmd

COMMON_DIR=	../common	# for Makefile.com
SRCS =		rcapstat.c \
		utils.c

LINTSRCS =	$(COMMON_DIR)/utils.c \
		rcapstat.c \
		$(STAT_COMMON_SRCS)

STATCOMMONDIR = $(SRC)/cmd/stat/common

STAT_COMMON_OBJS = timestamp.o
STAT_COMMON_SRCS = $(STAT_COMMON_OBJS:%.o=$(STATCOMMONDIR)/%.c)

$(NOT_RELEASE_BUILD)CPPFLAGS	+= -DDEBUG
CPPFLAGS			+= -I$(COMMON_DIR) -I$(STATCOMMONDIR)
LDLIBS				+= -lumem -lscf
LDFLAGS				+= $(MAPFILE.NGB:%=-M%)

LINTFLAGS			+= $(LDLIBS) -mnu

PROG =				rcapstat
OBJS =				$(SRCS:%.c=%.o) rcapd_conf.o

POFILES =			$(OBJS:%.o=%.po)
POFILE =			p$(PROG).po

CLOBBERFILES +=			rcapd_conf.c $(POFILES) $(POFILE)

.NO_PARALLEL:
.PARALLEL: $(OBJS) $(LINTFILES)

all: $(PROG) $(MAPFILE.NGB)

include ../Makefile.com

$(PROG): $(OBJS) $(STAT_COMMON_OBJS)
	$(LINK.c) $(OBJS) $(STAT_COMMON_OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o : $(STATCOMMONDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

clean:
	$(RM) $(OBJS) $(STAT_COMMON_OBJS)

lint:
	$(LINT.c) $(LINTSRCS)

$(ROOTBIN):
	$(MKDIR) -p $(ROOTBIN)

install: all $(ROOTBIN) $(ROOTPROG)

include ../../Makefile.targ
