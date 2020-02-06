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
# Copyright (c) 2019, Joyent, Inc.

PROG= tset

include ../Makefile.ucbcmd

FILEMODE=	755

LDLIBS =  -L$(ROOT)/usr/ucblib -R/usr/ucblib $(LDLIBS.cmd) -lucb -ltermcap

CPPFLAGS = -I$(SRC)/ucbhead $(CPPFLAGS.master)
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += $(CNOWARN_UNINIT)

# missing prototypes
SMATCH=off

ROOTSYMLINK= $(ROOTBIN)/reset

.KEEP_STATE:

all: $(PROG)

$(PROG):	$(PROG).c
	$(LINK.c) -o $@ $(PROG).c $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTBIN) $(ROOTPROG) $(ROOTSYMLINK)

$(ROOTSYMLINK):
	$(RM) $@
	$(SYMLINK) $(PROG) $@

clean:

include ../Makefile.ucbtarg
