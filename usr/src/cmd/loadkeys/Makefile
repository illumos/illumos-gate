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

PROG= loadkeys dumpkeys
sparc_SUBDIRS= type_4 type_6 type_101
ppc_SUBDIRS= type_101
i386_SUBDIRS= type_6 type_101
SUBDIRS= $($(MACH)_SUBDIRS)
SRCS=	$(PROG:%=%.c)

ROOTHELPER= $(ROOTLIB)/set_keyboard_layout
sparc_EXTRA_INSTALL_TARGETS=$(ROOTHELPER)
i386_EXTRA_INSTALL_TARGETS=$(ROOTHELPER)
EXTRA_INSTALL_TARGETS= $($(MACH)_EXTRA_INSTALL_TARGETS)

include ../Makefile.cmd

CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-uninitialized

CLOBBERFILES = $(PROG) loadkeys.c

.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

all:  $(PROG) $(SUBDIRS)

install: $(PROG) $(ROOTPROG) $(SUBDIRS) $(EXTRA_INSTALL_TARGETS)

$(ROOTLIB)/%: %
	$(INS.file)

# explicit yacc work for the NSE
#
loadkeys.c: loadkeys.y
	$(YACC.y) loadkeys.y
	mv y.tab.c $@

loadkeys: loadkeys.c
	$(LINK.c) -o $@ loadkeys.c $(LDLIBS)
	$(POST_PROCESS)

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint
_msg:=          TARGET= catalog

clobber:	$(SUBDIRS)
	$(RM) $(CLOBBERFILES)

clean:	$(SUBDIRS)

lint:
	$(LINT.c) dumpkeys.c $(LDLIBS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
