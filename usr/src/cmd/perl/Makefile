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
# Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../Makefile.cmd

all	:= TARGET = all
install	:= TARGET = install
clobber := TARGET = clobber
clean	:= TARGET = clean
test	:= TARGET = test

# PERL_LEGACY is versions of Perl still delivered through ON
PERL_VERSIONS = 5.10.0

.PARALLEL: $(PERL_VERSIONS)

all install test: $(PERL_VERSIONS)

clean: FRC

clobber: clean
	$(RM) -r $(PERL_VERSIONS)

#
# Perl is not lint-clean.  Fake up a target.
#
lint:
	@ $(ECHO) "usr/src/cmd/perl is not lint-clean: skipping"
	@ $(TRUE)

$(PERL_VERSIONS): FRC
	@ if [ ! -d $@ ]; then \
	    $(CP) -r skel $@; \
	fi
	@ cd $@; pwd; PERL_VERSION=$@ $(MAKE) $(TARGET)

FRC:
