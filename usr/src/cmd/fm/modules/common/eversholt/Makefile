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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
# eft.so (the eversholt DE)
#
# Copyright (c) 2018, Joyent, Inc.

.KEEP_STATE:

EVERSRCDIR=../../../eversholt/common

MODULE = eft
CLASS = common
DMOD = $(MODULE).so

YSRCS=escparse.y 
SRCS =	alloc.c check.c config.c eft.c eftread.c esclex.c eval.c evnv.c \
	fme.c iexpr.c io.c ipath.c itree.c lut.c literals.c out.c platform.c \
	ptree.c stable.c stats.c tree.c
DMOD_SRCS = eft_mdb.c

include ../../Makefile.plugin

CPPFLAGS += -DFMAPLUGIN -I$(EVERSRCDIR) -I.
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-implicit-function-declaration

# not linted
SMATCH=off

$(PROG) := LDFLAGS += -R/usr/lib/fm
$(PROG) := LDLIBS += -L$(ROOTLIB)/fm -ltopo

CLEANFILES += y.tab.h y.tab.c

esclex.o: escparse.o

%.o: $(EVERSRCDIR)/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

%.ln: $(EVERSRCDIR)/%.c
	$(LINT.c) -c $<

escparse.o: $(EVERSRCDIR)/escparse.y
	$(YACC) -dt $(EVERSRCDIR)/escparse.y
	$(COMPILE.c) -DYYDEBUG -c -o $@ y.tab.c
	$(CTFCONVERT_O)
