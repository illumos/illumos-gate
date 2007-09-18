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
# ident	"%Z%%M%	%I%	%E% SMI"

include $(SRC)/Makefile.master

.KEEP_STATE:

sparc_MACHDIR = sparc
i386_MACHDIR = intel

sparc_SUBDIRS = sparc sun4u sun4v
i386_SUBDIRS = intel i86pc i86xpv

MACHDIR = $($(MACH)_MACHDIR)
SUBDIRS = tools $($(MACH)_SUBDIRS) demo
TARGET =

all := TARGET = all
clean.lint := TARGET = clean.lint
clean := TARGET = clean
clobber := TARGET = clobber
dmods := TARGET = dmods
install := TARGET = install
install_h := TARGET = install_h
lint := TARGET = lint

all lint: $(SUBDIRS)

dmods install: install_h $(SUBDIRS)

install_h: FRC
	@cd common/mdb; pwd; $(MAKE) install_h

clean.lint clean: $(SUBDIRS) packages

clobber: $(SUBDIRS) packages

$($(MACH)_SUBDIRS): tools

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

pkg: install tools
	@cd packages; pwd; $(MAKE) install

FRC:

#
# Cross-reference customization: build the cross-reference only over the
# source directories, and ignore Makefiles and machine-generated source.
#
XRDIRS = common $(sparc_SUBDIRS) $(i386_SUBDIRS)
XRDEL = mdb_lex.c mdb_grammar.c Makefile*
