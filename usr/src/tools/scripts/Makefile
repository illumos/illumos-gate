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
	cstyle \
	elfcmp \
	flg.flp \
	genoffsets \
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
	mapfilechk \
	validate_pkg \
	wscheck \
	wsdiff

SCRIPTLINKS= \
	git-nits

MAN1ONBLDFILES= \
	Install.1onbld \
	bldenv.1onbld \
	bringovercheck.1onbld \
	cddlchk.1onbld \
	checkpaths.1onbld \
	check_rtime.1onbld \
	cstyle.1onbld \
	find_elf.1onbld \
	flg.flp.1onbld \
	git-pbchk.1onbld \
	hdrchk.1onbld \
	interface_check.1onbld \
	interface_cmp.1onbld \
	jstyle.1onbld \
	mapfilechk.1onbld \
	nightly.1onbld \
	onu.1onbld \
	sccscheck.1onbld \
	webrev.1onbld \
	which_scm.1onbld \
	ws.1onbld \
	wsdiff.1onbld \
	xref.1onbld

MAN1ONBLDLINKS= \
	git-nits.1onbld

MAKEFILES= \
	xref.mk

ETCFILES= \
	its.conf \
	its.reg

EXCEPTFILES= \
	check_rtime \
	interface_check \
	interface_cmp

CLEANFILES = $(SHFILES) $(PERLFILES) $(PYFILES) bldenv.1onbld onu.sh

onu.sh:	onu.sh.in
	$(SED) -e "s:@PYTHON_VERSION@:$(PYTHON_VERSION):g" < onu.sh.in > $@

include ../Makefile.tools

ROOTONBLDSCRIPTLINKS = $(SCRIPTLINKS:%=$(ROOTONBLDBIN)/%)
ROOTONBLDMAN1ONBLDLINKS = $(MAN1ONBLDLINKS:%=$(ROOTONBLDMAN1ONBLD)/%)

$(ROOTONBLDETCFILES)		:= FILEMODE=	644
$(ROOTONBLDEXCEPTFILES)		:= FILEMODE=	644
$(ROOTONBLDPERLMODULES)		:= FILEMODE=	644
$(ROOTONBLDMAKEFILES)		:= FILEMODE=	644
$(ROOTONBLDMAN1ONBLDFILES)	:= FILEMODE=	644

.KEEP_STATE:

all:	$(SHFILES) $(PERLFILES) $(PERLMODULES) $(PYFILES) \
	$(MAN1ONBLDFILES) $(MAKEFILES)

$(ROOTONBLDBIN)/git-nits:
	$(RM) $(ROOTONBLDBIN)/git-nits
	$(SYMLINK) git-pbchk $(ROOTONBLDBIN)/git-nits

$(ROOTONBLDMAN1ONBLD)/git-nits.1onbld:
	$(RM) $(ROOTONBLDMAN1ONBLD)/git-nits.1onbld
	$(SYMLINK) git-pbchk.1onbld $(ROOTONBLDMAN1ONBLD)/git-nits.1onbld

install: all .WAIT $(ROOTONBLDSHFILES) $(ROOTONBLDPERLFILES)		\
		$(ROOTONBLDPERLMODULES) $(ROOTONBLDPYFILES)		\
		$(ROOTONBLDSCRIPTLINKS) $(ROOTONBLDMAN1ONBLDFILES)	\
		$(ROOTONBLDMAKEFILES) $(ROOTONBLDETCFILES)		\
		$(ROOTONBLDEXCEPTFILES) $(ROOTONBLDMAN1ONBLDLINKS)

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

bldenv.1onbld: bldenv
	$(RM) "$@"
	(set +o errexit ; ksh93 $? --nroff ; true) 2>&1 | \
	sed -e 's/\.DS/.nf/g;s/\.DE/.fi/' \
	-e 's/\.TH BLDENV 1/.TH BLDENV 1ONBLD/' \
	-e 's/(1)/(1ONBLD)/' > "$@"

nightly: nightly.sh stdenv.sh
	$(RM) "$@"
	sed -e '/# STDENV_START/ r stdenv.sh' nightly.sh > nightly
	$(CHMOD) +x "$@"

include ../Makefile.targ

