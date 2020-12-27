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
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.

SHELL= /usr/bin/ksh93

include ../../Makefile.cmd

.KEEP_STATE:

# Set common AST build flags (e.g., needed to support the math stuff).
include ../Makefile.ast

ASTSRC= $(C_AST)/src/cmd/msgcc

# build rules
CPPFLAGS= \
        $(DTEXTDOM) $(DTS_ERRNO) \
        -I$(ROOT)/usr/include/ast \
	-I$(ROOT)/usr/include \
	-D_PACKAGE_ast \
	'-DUSAGE_LICENSE=\
	    "[-author?Glenn Fowler <gsf@research.att.com>]"\
	    "[-copyright?Copyright (c) 2000-2012 AT&T Intellectual Property]"\
	    "[-license?http://www.eclipse.org/org/documents/epl-v10.html]" \
	    "[--catalog?msgcc]"'

CFLAGS += $(ASTCFLAGS)

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-empty-body
CERRWARN += $(CNOWARN_UNINIT)

# not linted
SMATCH=off

LDLIBS += -last
msgcpp   := LDLIBS += -lpp

CPROG= msgcvt msggen msgget msgcpp
PROG= msgcc $(CPROG)

all: $(PROG)

# This target should use "shcomp" in the future
msgcc:	$(ASTSRC)/msgcc.sh
	rm -f msgcc ; \
	{ \
		print "#!/usr/bin/ksh93" ; \
		print "export PATH=/usr/ast/bin:/usr/xpg6/bin:/usr/xpg4/bin:/usr/bin:\$${PATH}" ; \
		print "builtin date" ; \
		cat "$(ASTSRC)/msgcc.sh" ; \
	} >msgcc ; \
	chmod a+rx msgcc

ROOTCMDDIR=$(ROOT)/usr/ast/bin

install: all $(ROOTCMD)
check clean install_h _feature:

include ../../Makefile.targ
POFILE= msgcpp.po

# Create dummy file since AST/ksh/msgcc doesn't use *.po files
msgcpp.po:
	$(RM) $@
	$(TOUCH) $(@)

$(CPROG):
	$(LINK.c) -o $@ $(ASTSRC)/$@.c $(LDLIBS)
	$(POST_PROCESS)

FRC:
.PARALLEL: $(PROG)
