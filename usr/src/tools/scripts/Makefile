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

SHELL=/usr/bin/ksh93

SHFILES= \
	Install \
	bfu \
	bindrop \
	bldenv \
	build_cscope \
	bringovercheck \
	checkpaths \
	checkproto \
	cryptodrop \
	cstyle \
	elfcmp \
	flg.flp \
	genoffsets \
	hgsetup \
	keywords \
	makebfu \
	mkbfu \
	mkclosed \
	nightly \
	onu \
	protocmp.terse \
	sccscheck \
	sccscp \
	sccshist \
	sccsmv \
	sccsrm \
	webrev \
	which_scm \
	ws \
	wx \
	wx2hg \
	xref

PERLFILES= \
	check_rtime \
	find_elf \
	interface_check \
	interface_cmp \
	jstyle \
	mkreadme_osol \
	mktpl \
	validate_flg \
	validate_paths \
	wdiff

PERLMODULES= \
	onbld_elfmod.pm


PYFILES= \
 	cddlchk \
 	copyrightchk \
 	hdrchk \
 	hg-active \
 	mapfilechk \
 	rtichk \
	validate_pkg \
 	wsdiff

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
	hdrchk.1 \
	interface_check.1 \
	interface_cmp.1 \
	hgsetup.1 \
	jstyle.1 \
	mapfilechk.1 \
	nightly.1 \
	onu.1 \
	sccscheck.1 \
	sccscp.1 \
	sccsmv.1 \
	sccsrm.1 \
	webrev.1 \
	which_scm.1 \
	ws.1 \
	wsdiff.1 \
	wx.1 \
	wx2hg.1 \
	xref.1

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


$(ROOTONBLDETCFILES)	:= FILEMODE=	644
$(ROOTONBLDEXCEPTFILES)	:= FILEMODE=	644
$(ROOTONBLDPERLMODULES)	:= FILEMODE=	644
$(ROOTONBLDMAKEFILES)	:= FILEMODE=	644
$(ROOTONBLDMAN1FILES)	:= FILEMODE=	644

.KEEP_STATE:

all:	$(SHFILES) $(PERLFILES) $(PERLMODULES) $(PYFILES) \
	$(MAN1FILES) $(MAKEFILES)

install: all .WAIT $(ROOTONBLDSHFILES) $(ROOTONBLDPERLFILES)	\
		$(ROOTONBLDPERLMODULES) $(ROOTONBLDPYFILES)	\
		$(ROOTONBLDMAN1FILES) $(ROOTONBLDMAKEFILES)	\
		$(ROOTONBLDETCFILES) $(ROOTONBLDEXCEPTFILES)

clean:
	$(RM) $(CLEANFILES)

bldenv: bldenv.sh stdenv.sh
	$(RM) "$@"
	sed -e '/# STDENV_START/ r stdenv.sh' bldenv.sh > "$@"
	# Check for shell lint and fail if we hit warings
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

