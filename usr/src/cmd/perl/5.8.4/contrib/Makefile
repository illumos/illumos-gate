#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

include ../../../Makefile.cmd
include ../Makefile.perlcfg

#
# Extra arguments needed to fool MakeMaker into building in the distrib tree.
# Note we fake up an extra directory for contrib scripts under distrib - the
# modified installperl knows how to handle the contents.
#
PERL_MM_ARGS += INST_ARCHLIB=$(PERL_DISTRIB)/lib INST_LIB=$(PERL_DISTRIB)/lib \
    INST_SCRIPT=$(PERL_DISTRIB)/contrib_bin \
    INST_BIN=$(PERL_DISTRIB)/contrib_bin  PERL_SRC=$(PERL_DISTRIB)

# All SMI perl libraries should be prefixed with this.
SUN_SOLARIS = Sun/Solaris

# Add any XS extensions here.
PERL_DYNAMIC_EXT = \
    $(SUN_SOLARIS)/Utils \
    $(SUN_SOLARIS)/Intrs \
    $(SUN_SOLARIS)/Project \
    $(SUN_SOLARIS)/Task \
    $(SUN_SOLARIS)/Exacct \
    $(SUN_SOLARIS)/Privilege \
    $(SUN_SOLARIS)/Ucred

CLOSED_PERL_EXT += $(SUN_SOLARIS)/Kstat

# Add any pure-perl extensions here.
PERL_NONXS_EXT = \
    $(SUN_SOLARIS)/BSM \
    $(SUN_SOLARIS)/PerlGcc

PERL_EXT = $(PERL_DYNAMIC_EXT) $(PERL_NONXS_EXT)
PERL_EXT_MAKEFILES = $(PERL_EXT:%=%/Makefile)

ALL_EXT = $(PERL_EXT)
ALL_EXT_MAKEFILES = $(PERL_EXT_MAKEFILES)

$(CLOSED_BUILD)ALL_EXT += $(CLOSED_PERL_EXT)
$(CLOSED_BUILD)ALL_EXT_MAKEFILES += $(CLOSED_PERL_EXT:%=%/Makefile)

all: copy_contrib $(ALL_EXT_MAKEFILES) $(ALL_EXT)

.PARALLEL: $(ALL_EXT_MAKEFILES) $(ALL_EXT)

#
# Note: this is a dummy install target; during 'make all' this Makefile
# populates ../distrib/lib with the modules that it is responsible for building,
# and the install target of ../distrib/Makefile subsequently copies the modules
# into the proto area.
#
install: all

#
# copy_contrib copies the clearfiles from ../../contrib to here.
#
copy_contrib:   ../../contrib/copy_contrib
	@ ../../contrib/copy_contrib ../../contrib . $(PERL_EXT)
	@ if [ -d $(CLOSED)/cmd/perl/contrib -a \
	    -n "$(CLOSED_PERL_EXT)" ]; then \
		../../contrib/copy_contrib $(CLOSED)/cmd/perl/contrib \
		    . $(CLOSED_PERL_EXT); \
	fi

clean:
	-@ $(PERL_MM_ENV); \
	for ext in $(ALL_EXT); do \
		if [ -d $$ext ]; then \
			( \
			cd $$ext; pwd; \
			[ -f Makefile.old ] && mf=Makefile.old; \
			[ -f Makefile ] && mf=Makefile; \
			[ ! -z "$$mf" ] && $(MAKE) -f $$mf clean; \
			) \
		fi \
	done

clobber:
	-@ $(PERL_MM_ENV); \
	for ext in $(ALL_EXT); do \
		if [ -d $$ext ]; then \
			( \
			cd $$ext; pwd; \
			[ -f Makefile.old ] && mf=Makefile.old; \
			[ -f Makefile ] && mf=Makefile; \
			[ ! -z "$$mf" ] && $(MAKE) -f $$mf realclean; \
			); \
			$(RM) -r $$ext; \
		fi \
	done

test: all
	@ $(PERL_MM_ENV); $(PERL_LD_ENV); \
	for ext in $(ALL_EXT); do \
		( \
		cd $$ext; pwd; \
		[ -f Makefile.old ] && mf=Makefile.old; \
		[ -f Makefile ] && mf=Makefile; \
		[ ! -z "$$mf" ] && $(MAKE) -f $$mf test; \
		) \
	done

# Pattern-matching rule for Makefiles.
%/Makefile: %/Makefile.PL $(PERL_CONFIGDEP)
	@ cd $(@D); pwd; $(RUN_MINIPERL) $(<F) $(PERL_MM_ARGS) > /dev/null

# Pattern-matching rule for extensions.
$(SUN_SOLARIS)/%: $(SUN_SOLARIS)/%/Makefile FRC
	@ cd $@; pwd; $(PERL_MM_ENV); $(MAKE) all

#
# Additional rule to make sure changes to the ::Exacct sub-module Makefile.PL
# files results in the parent Makefile.PL being rerun.
#
$(SUN_SOLARIS)/Exacct/Makefile: $(SUN_SOLARIS)/Exacct/Makefile.PL \
    $(SUN_SOLARIS)/Exacct/Catalog/Makefile.PL \
    $(SUN_SOLARIS)/Exacct/File/Makefile.PL \
    $(SUN_SOLARIS)/Exacct/Object/Makefile.PL \
    $(PERL_CONFIGDEP)
	@ cd $(SUN_SOLARIS)/Exacct; pwd; \
	$(RUN_MINIPERL) Makefile.PL $(PERL_MM_ARGS) > /dev/null

FRC:
