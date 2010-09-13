#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/sort/Makefile
#

PROG = sort
XPG4PROG = sort

include ../Makefile.cmd

SRCS =	common/check.c common/fields.c common/initialize.c common/internal.c \
	common/main.c common/merge.c common/options.c common/streams.c \
	common/streams_array.c common/streams_mmap.c common/streams_stdio.c \
	common/streams_wide.c common/utility.c
POFILES = $(SRCS:common/%.c=./%.po)
CLOBBERFILES = $(DCFILE) $(POFILE) $(POFILES)

.KEEP_STATE:

$(XPG4) := CPPFLAGS += -DXPG4
XGETFLAGS += -a -x sort.xcl

SUBDIRS =        $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all     :=      TARGET = all
install :=      TARGET = install
clean   :=      TARGET = clean
clobber :=      TARGET = clobber
lint    :=      TARGET = lint
debug	:=	TARGET = debug
convert :=      TARGET = convert
invoke  :=      TARGET = invoke
stats   :=      TARGET = stats

all : $(SUBDIRS)

clean clobber lint : $(SUBDIRS)

debug convert invoke stats : $(SUBDIRS)

install : $(SUBDIRS)
	-$(RM) $(ROOTPROG)
	-$(LN) $(ISAEXEC) $(ROOTPROG)

$(POFILE) : $(POFILES)
	echo $(SRCS)
	echo $(POFILES)
	-$(RM) $@
	$(CAT) $(POFILES) > $@

%.po : common/%.c
	$(RM) messages.po
	$(XGETTEXT) -c TRANSLATION_NOTE $<
	$(SED) -e '/^domain/d' messages.po > $@
	$(RM) messages.po

$(SUBDIRS) : FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC :

include ../Makefile.targ
