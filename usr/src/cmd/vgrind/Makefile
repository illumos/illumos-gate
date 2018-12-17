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
# Copyright (c) 2018, Joyent, Inc.

#
# These are the objects associated with the overall vgrind command.
#
VFONTEDPR=	vfontedpr
RETEST= 	retest
MACROS=		tmac.vgrind
LANGDEFS=	vgrindefs
KSHPROG=	vgrind

#
# These macros captures objects that ultimately will be installed in
# (respectively) /usr/bin, /usr/lib, and /usr/share/lib.
#
# Note also that retest is used strictly as a test program and is never
# installed.  We omit it here, so that the NSE doesn't spend cycles
# on it when acquiring and reconciling.
#
PROG= 		$(KSHPROG)
LIBPROG= 	$(VFONTEDPR) $(LANGDEFS)
TMACPROG=	$(MACROS)

VFONTEDPROBJS=	vfontedpr.o vgrindefs.o regexp.o
RETESTOBJS=	retest.o regexp.o

RETESTSRC=	$(RETESTOBJS:%.o=%.c)

OBJS= $(VFONTEDPROBJS) $(RETESTOBJS)
SRCS= $(OBJS:%.o=%.c)

#
# We can get away simply with omitting TMACPROGS to protect
# tmac.vgrind, since it's the only entry in that macro.
#
CLOBBERFILES=	$(LIBPROG) $(RETEST)

include ../Makefile.cmd

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-unused-function

# not linted
SMATCH=off

#
# Message catalog
#
POFILES= $(OBJS:%.o=%.po)
POFILE= vgrind.po
POFILE_KSH= vgrind_ksh.po

#
# Abbreviation for future use.
#
ROOTTMAC= $(ROOT)/usr/share/lib/tmac

#
# Override macro definitions from Makefile.cmd.  Necessary because
# we're building targets for multiple destinations.
#
ROOTLIBPROG= $(LIBPROG:%=$(ROOT)/usr/lib/%)
ROOTTMACPROG= $(TMACPROG:%=$(ROOTTMAC)/%)

#
# Conditional assignments pertinent to installation.
#
$(ROOTLIB)/$(LANGDEFS) 	:= FILEMODE= $(LIBFILEMODE)
$(ROOTTMACPROG) 	:= FILEMODE= 0644

#
# The standard set of rules doesn't know about installing into
# subdirectories of /usr/share/lib, so we have to roll our own.
#
$(ROOTTMAC)/%: %
	$(INS.file)

.KEEP_STATE:

#
# retest appears here only in source form; see comment above for PROG.
#
all:	$(PROG) $(LIBPROG) $(TMACPROG) $(RETESTSRC)

#
# message catalog
#
$(POFILE): $(POFILES) $(POFILE_KSH)
	rm -f $@
	cat $(POFILES) $(POFILE_KSH) > $@

$(VFONTEDPR): $(VFONTEDPROBJS)
	$(CC) -o $@ $(VFONTEDPROBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

$(LANGDEFS):	$(LANGDEFS).src
	$(CP) $? $@

$(RETEST): $(RETESTOBJS)
	$(CC) -o $@ $(RETESTOBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

#
# We add all as a dependent to make sure that the install pattern
# matching rules see everything they should.  (This is a safety net.)
#
# XXX:	ROOTTMAC shouldn't appear as a dependent; it's here as a
# 	bandaid(TM) until /usr/lib/tmac becomes a symlink to
#	/usr/share/lib/tmac.
#
install: all $(ROOTTMAC) $(ROOTPROG) $(ROOTLIBPROG) $(ROOTTMACPROG)

# XXX: see above.
$(ROOTTMAC):
	$(INS.dir)

clean:
	$(RM) $(OBJS)

#
# Don't worry about linting retest.
#
lint:=	SRCS = $(VFONTEDPROBJS:%.o=%.c)
lint: lint_SRCS

include ../Makefile.targ
