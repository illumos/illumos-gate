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
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
# Copyright 2016 Toomas Soome <tsoome@me.com>
# Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
# Copyright 2019 Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2021 Jason King
#

include ../Makefile.master

# Bootstrap problem: some utilities are pre-requisites for building everything
# else:
#    - smatch - as it is a shadow compiler
#    - cw - as it is used to drive builds
#    - install.bin - being the 'install' target dependency
#    - ctf - being used to generate CTF data
#
# Anything built before 'install.bin' is present must override binary
# installation rules in their makefiles. This includes the Makefile for
# 'install.bin' itself.
BOOT_SUBDIRS=		\
	smatch		\
	.WAIT		\
	cw		\
	.WAIT		\
	install.bin	\
	.WAIT		\
	ctf		\
	yacc		\
	lex

COMMON_SUBDIRS=		\
	codesign	\
	cscope-fast	\
	env		\
	find_elf	\
	findunref	\
	lintdump	\
	make		\
	makesoftcore	\
	manlink		\
	ndrgen		\
	onbld		\
	protocmp	\
	protolist	\
	scripts		\
	sgs		\
	svc

#
#  special versions of commands for use only in build
#
UNSHIPPED_SUBDIRS =		\
	$(SGSMSG)		\
	$(SGSLIBCONV)		\
	$(SGSLIBELF)		\
	$(SGSLIBLDDBG)		\
	$(SGSLIBLD)		\
	$(SGSLD)		\
	geniconvtbl		\
	localedef		\
	mandoc			\
	rpcgen			\
	tic			\
	vtfontcvt		\
	zic

i386_SUBDIRS=			\
	cpcgen			\
	elfextract		\
	mbh_patch		\
	btxld

SUBDIRS=			\
	$($(MACH)_SUBDIRS)	\
	$(COMMON_SUBDIRS)	\
	$(UNSHIPPED_SUBDIRS)

include Makefile.tools

ROOTDIRS=					\
	$(ROOTOPT)				\
	$(ROOTONBLD)				\
	$(ROOTONBLD)/bin			\
	$(ROOTONBLD)/bin/$(MACH)		\
	$(ROOTONBLD)/bin/$(MACH64)		\
	$(ROOTONBLD)/lib			\
	$(ROOTONBLD)/lib/$(MACH)		\
	$(ROOTONBLD)/lib/$(MACH)/64		\
	$(ROOTONBLD)/lib/perl			\
	$(ROOTONBLD)/env			\
	$(ROOTONBLD)/etc			\
	$(ROOTONBLD)/etc/exception_lists	\
	$(ROOTONBLD)/share			\
	$(ROOTONBLD)/share/lib			\
	$(ROOTONBLD)/share/lib/ccs		\
	$(ROOTONBLD)/man			\
	$(ROOTONBLD)/man/man1onbld

ROOTDIRS +=							\
	$(ROOTONBLD)/lib/python$(PYTHON3_VERSION)				\
	$(ROOTONBLD)/lib/python$(PYTHON3_VERSION)/onbld				\
	$(ROOTONBLD)/lib/python$(PYTHON3_VERSION)/onbld/__pycache__		\
	$(ROOTONBLD)/lib/python$(PYTHON3_VERSION)/onbld/Checks			\
	$(ROOTONBLD)/lib/python$(PYTHON3_VERSION)/onbld/Checks/__pycache__	\
	$(ROOTONBLD)/lib/python$(PYTHON3_VERSION)/onbld/Scm			\
	$(ROOTONBLD)/lib/python$(PYTHON3_VERSION)/onbld/Scm/__pycache__

all :=		TARGET= install
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

.KEEP_STATE:

#
# Only create directories in the tools proto area when doing an actual
# build, not a clean or clobber.
#
DOROOTDIRS= $(ROOTDIRS)
clobber:= DOROOTDIRS=
clean:= DOROOTDIRS=

clobber:= DOROOTONBLDLIBPY=
clean:= DOROOTONBLDLIBPY=

all install: $(SUBDIRS)

clean: $(SUBDIRS)

clobber: $(SUBDIRS)
	$(RM) -rf $(TOOLS_PROTO)

bootstrap: $(BOOT_SUBDIRS)

_msg: $(MSGSUBDIRS)

.PARALLEL: $(SUBDIRS)

$(SUBDIRS): $(BOOT_SUBDIRS)

$(BOOT_SUBDIRS) $(SUBDIRS): $$(DOROOTDIRS) $$(DOROOTONBLDLIBPY) FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

# Assume we don't have the install.bin available yet
$(ROOTDIRS):
	$(MKDIR) -p -m $(DIRMODE) $@

$(ROOTONBLDLIBPY): $(ROOTDIRS)
	$(RM) -r $@; $(SYMLINK) python$(PYTHON3_VERSION) $@

FRC:
