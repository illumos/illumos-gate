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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../../Makefile.cmd

# To turn KEEP_STATE off the following two environment variables must be unset.
KEEP_STATE_OFF = unset KEEP_STATE SUNPRO_DEPENDENCIES

# Perl installs files we don't want to ship, so we install to a
# staging area to postprocess and install the result to $(ROOT)
STAGE = $(SRC)/cmd/perl/$(PERL_VERSION)/staging

PERL=$(ADJUNCT_PROTO)/usr/perl5/$(PERL_VERSION)/bin/perl

PERL_MM_ARGS = INSTALLDIRS=perl CC='$(CC)' LD='$(CC)'

# Prefix for Solaris-specific extensions that are maintained by
# Sun/Oracle.
SUN_SOLARIS = Sun/Solaris

# Add any XS extensions here.
PERL_DYNAMIC_EXT = \
    $(SUN_SOLARIS)/Utils \
    $(SUN_SOLARIS)/Kstat \
    $(SUN_SOLARIS)/Intrs \
    $(SUN_SOLARIS)/Project \
    $(SUN_SOLARIS)/Task \
    $(SUN_SOLARIS)/Exacct \
    $(SUN_SOLARIS)/Privilege \
    $(SUN_SOLARIS)/Lgrp \
    $(SUN_SOLARIS)/Ucred

# Add any pure-perl extensions here.
PERL_NONXS_EXT = \
    $(SUN_SOLARIS)/BSM \
    $(SUN_SOLARIS)/PerlGcc \
    $(SUN_SOLARIS)/Pg

PERL_EXT = $(PERL_DYNAMIC_EXT) $(PERL_NONXS_EXT)
PERL_EXT_MAKEFILES = $(PERL_EXT:%=%/Makefile)

all: copy_contrib $(PERL_EXT_MAKEFILES) $(PERL_EXT)

.PARALLEL: $(PERL_EXT_MAKEFILES) $(PERL_EXT)

install: all
	for ext in $(PERL_EXT); do \
		if [ -d $$ext ]; then \
			( \
			cd $$ext; pwd; \
			$(KEEP_STATE_OFF); $(MAKE) $(PERL_MM_ARGS) \
				DESTDIR=$(STAGE) install; \
			cd $(STAGE); \
			find . \( -name ".packlist" -o -name "perllocal.pod" \) \
				-exec $(RM) {} \; ; \
			/usr/bin/pax -rw -pe ./*  ${ROOT} ; \
			) \
		else \
			/bin/false; \
		fi \
	done

#
# copy_contrib copies the clearfiles from ../contrib to here.
#
copy_contrib:
	@ $(KSH93) ../contrib/copy_contrib.sh ../contrib . $(PERL_EXT)

clean:
	for ext in $(PERL_EXT); do \
		if [ -d $$ext ]; then \
			( \
			cd $$ext; pwd; \
			$(KEEP_STATE_OFF); $(MAKE) clean; \
			) \
		fi \
	done

# Remove Sun/Solaris
clobber:
	@ $(RM) -r Sun

test: all
	for ext in $(PERL_EXT); do \
		( \
		cd $$ext; pwd; \
		$(KEEP_STATE_OFF); $(MAKE) test; \
		) \
	done

#
# Ensure that the extension's makefile is built before
# trying to build the extension
#
%/Makefile: %/Makefile.PL $(PERL_CONFIGDEP)
	@ cd $(@D); pwd; $(PERL) $(<F) $(PERL_MM_ARGS) 2>&1 /dev/null

# Pattern-matching rule for extensions.
$(SUN_SOLARIS)/%: $(SUN_SOLARIS)/%/Makefile FRC
	@ cd $@; pwd; $(KEEP_STATE_OFF) ; \
		$(PERL_MM_ARGS) $(MAKE) DESTDIR=$(STAGE) all

FRC:
