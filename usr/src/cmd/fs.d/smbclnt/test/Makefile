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
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include $(SRC)/cmd/Makefile.cmd

PROG=	srvenum srvinfo tconn
OBJS = $(PROG:%=%.o)
SRCS = $(OBJS:%.o=%.c)

# ROOTFS_PROG=	$(LIBPROG)
# include		../../Makefile.fstype

ROOTOPTPKG = $(ROOT)/opt/smbcl-tests
TESTDIR = $(ROOTOPTPKG)/tests
INST_CMDS = $(PROG:%=$(TESTDIR)/%)

# OBJS=	$(LIBPROG).o
# SRCS=	$(LIBPROG).c $(FSLIBSRC)

CPPFLAGS += -I../../../../uts/common
CPPFLAGS += -I../../../../lib/libsmbfs

LDLIBS += -R '$$ORIGIN/../../../usr/lib'
LDLIBS += -lsmbfs
LINTLIBS= -L$(ROOTLIB) -lsmbfs

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-unused-variable
C99MODE= $(C99_ENABLE)

LINTFLAGS += -erroff=E_FUNC_RET_ALWAYS_IGNOR2

# CLOBBERFILES	+= $(LIBPROG)

all:	$(PROG)

install: all $(ROOTOPTPKG) $(TESTDIR) $(INST_CMDS)

lint:
	for f in $(SRCS); do ;\
	$(LINT.c) $$f $(LINTLIBS) ; done

clobber: clean
	-$(RM) $(PROG)

clean:     
	-$(RM) $(OBJS)

$(ROOTOPTPKG):
	$(INS.dir)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)

.KEEP_STATE:
