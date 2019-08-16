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

PROG= diff diffh
SRCS=	$(PROG:%=%.c)
BINDIFF= diff
LIBDIFFH= diffh

include ../Makefile.cmd

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-address

#
# for messaging catalog
#
POFILE= diff.po
DCFILE= diff.dc
#XGETFLAGS += -a -x diff.xcl

ROOTBINDIFF = $(BINDIFF:%=$(ROOTBIN)/%)
ROOTLIBDIFFH = $(LIBDIFFH:%=$(ROOTLIB)/%)

.KEEP_STATE:

all: $(PROG) 

#
# Use private rule
#
$(POFILE):
	$(RM) $@
	$(COMPILE.cpp)   $(SRCS) > diff.po.i
	$(XGETTEXT) $(XGETFLAGS) diff.po.i
	sed "/^domain/d"        messages.po     > $@
	$(RM)  diff.po.i messages.po

$(DCFILE):
	$(RM) $@
	$(COMPILE.cpp)   $(SRCS) > diff.dc.i
	$(XGETTEXT) -c TRANSLATION_NOTE_FOR_DC -t diff.dc.i
	sed "/^domain/d"        messages.po     > $@
	$(RM)  diff.dc.i messages.po

install: all $(ROOTBINDIFF) $(ROOTLIBDIFFH)

clean:

lint:
	$(LINT.c) diff.c $(LDLIBS)
	$(LINT.c) diffh.c $(LDLIBS)

include ../Makefile.targ
