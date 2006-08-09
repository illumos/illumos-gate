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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

.PARALLEL:

#############################################################################

NAME = pcidr_plugin
LIBRARY = $(NAME).a
VERS =

TOPOBJECTS = pcidr_common.o
LOCOBJECTS = $(NAME).o pcidr_cfga.o
OBJECTS = $(LOCOBJECTS) $(TOPOBJECTS)

include $(SRC)/lib/Makefile.lib
include $(SRC)/cmd/pcidr/Makefile.com
#############################################################################

THISDIR = $(TOP)/plugins/default

# SRCS is used by the lintcheck rule and is defined as
# $(OBJECTS:%.o=$(SRCDIR)/%.c) where SRCDIR is this directory; set SRCS to a
# list of source paths if it differ from the default
#

SRCDIR = .
SRCS = $(TOPOBJECTS:%.o=$(TOP)/%.c) $(LOCOBJECTS:%.o=$(SRCDIR)/%.c)

LIBS = $(DYNLIB)

LDLIBS += -lcfgadm -lnvpair

HDRSRCS_SH = ls -1 $(THISDIR)/*.h
HDRSRCS = $(HDRSRCS_SH:sh)
CPPFLAGS += -I$(THISDIR)

# override LIBLINKS so that ROOTLIBS or anything else won't match the install
# target "$(ROOTLIBDIR)/$(LIBLINKS)"
#
LIBLINKS = __no_liblinks__

.KEEP_STATE:
#############################################################################

all: $(LIBS)
install: $(ROOTLIBS)
clean:
clobber:
lint: lintcheck

$(ROOTLIBS): all

# Note that we can't do:
#	$(TOPOBJECTS:%=objs/%) := SRCDIR = $(TOP)
# and let the make do the rest because the man page states:
# "Notice that if a conditional macro is referred to in a  dependency list,
#  the $ must be delayed (use $$ instead)."
#
# So we must add new targets for our TOPOBJECTS items but follow
# the existing pic/*.o and objs/*.o rules in lib/Makefile.targ
#
objs/%.o pics/%.o: $(TOP)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
include ../Makefile.targ
