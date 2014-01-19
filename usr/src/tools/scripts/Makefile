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
#
# Copyright 2010, Richard Lowe

SHELL=/usr/bin/ksh93

SHFILES= \
	Install \
	bldenv \
	build_cscope \
	bringovercheck \
	checkpaths \
	checkproto \
	cstyle \
	elfcmp \
	flg.flp \
	genoffsets \
	hgsetup \
	nightly \
	onu \
	protocmp.terse \
	sccscheck \
	webrev \
	which_scm \
	ws \
	xref

PERLFILES= \
	check_rtime \
	find_elf \
	interface_check \
	interface_cmp \
	jstyle \
	validate_flg \
	validate_paths \
	wdiff

PERLMODULES= \
	onbld_elfmod.pm \
	onbld_elfmod_vertype.pm


PYFILES= \
	cddlchk \
	copyrightchk \
	git-pbchk \
	hdrchk \
	hg-active \
	mapfilechk \
	validate_pkg \
	wsdiff

SCRIPTLINKS= \
	git-nits

MAN1FILES= \
	Install.1 \
	bldenv.1 \
	bringovercheck.1 \
	cddlchk.1 \
	checkpaths.1 \
	check_rtime.1 \
	cstyle.1 \
	find_elf.1 \
	flg.flp.1 \
	git-pbchk.1 \
	hdrchk.1 \
	interface_check.1 \
	interface_cmp.1 \
	hgsetup.1 \
	jstyle.1 \
	mapfilechk.1 \
	nightly.1 \
	onu.1 \
	sccscheck.1 \
	webrev.1 \
	which_scm.1 \
	ws.1 \
	wsdiff.1 \
	xref.1

MAN1LINKS= \
	git-nits.1

MAKEFILES= \
	xref.mk

ETCFILES= \
	hgstyle \
	its.conf \
	its.reg

EXCEPTFILES= \
	check_rtime \
	interface_check \
	interface_cmp

CLEANFILES = $(SHFILES) $(PERLFILES) $(PYFILES) bldenv.1

include ../Makefile.tools

ROOTONBLDSCRIPTLINKS = $(SCRIPTLINKS:%=$(ROOTONBLDBIN)/%)
ROOTONBLDMAN1LINKS = $(MAN1LINKS:%=$(ROOTONBLDMAN1)/%)

$(ROOTONBLDETCFILES)	:= FILEMODE=	644
$(ROOTONBLDEXCEPTFILES)	:= FILEMODE=	644
$(ROOTONBLDPERLMODULES)	:= FILEMODE=	644
$(ROOTONBLDMAKEFILES)	:= FILEMODE=	644
$(ROOTONBLDMAN1FILES)	:= FILEMODE=	644

.KEEP_STATE:

all:	$(SHFILES) $(PERLFILES) $(PERLMODULES) $(PYFILES) \
	$(MAN1FILES) $(MAKEFILES)

$(ROOTONBLDBIN)/git-nits:
	$(RM) $(ROOTONBLDBIN)/git-nits
	$(SYMLINK) git-pbchk $(ROOTONBLDBIN)/git-nits

$(ROOTONBLDMAN1)/git-nits.1:
	$(RM) $(ROOTONBLDMAN1)/git-nits.1
	$(SYMLINK) git-pbchk.1 $(ROOTONBLDMAN1)/git-nits.1

install: all .WAIT $(ROOTONBLDSHFILES) $(ROOTONBLDPERLFILES)	\
		$(ROOTONBLDPERLMODULES) $(ROOTONBLDPYFILES)	\
		$(ROOTONBLDSCRIPTLINKS) $(ROOTONBLDMAN1FILES)	\
		$(ROOTONBLDMAKEFILES) $(ROOTONBLDETCFILES)	\
		$(ROOTONBLDEXCEPTFILES) $(ROOTONBLDMAN1LINKS)

clean:
	$(RM) $(CLEANFILES)

bldenv: bldenv.sh stdenv.sh
	$(RM) "$@"
	sed -e '/# STDENV_START/ r stdenv.sh' bldenv.sh > "$@"
	# Check for shell lint and fail if we hit warnings
	shlintout="$$( /usr/bin/ksh93 -n "$@" 2>&1 )" ; \
		[[ "$${shlintout}" != "" ]] && \
		{ print -r -- "$${shlintout}" ;	false ; } || true
	$(CHMOD) +x "$@" 

bldenv.1: bldenv
	$(RM) "$@"
	(set +o errexit ; ksh93 $? --nroff ; true) 2>&1 | \
	sed 's/\.DS/.nf/g;s/\.DE/.fi/' > "$@"

nightly: nightly.sh stdenv.sh
	$(RM) "$@"
	sed -e '/# STDENV_START/ r stdenv.sh' nightly.sh > nightly
	$(CHMOD) +x "$@" 

include ../Makefile.targ

