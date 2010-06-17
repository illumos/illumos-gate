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
# Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
#

require 5.8.4;
use strict;
use warnings;
use ExtUtils::MakeMaker;

#
# This module uses non-shipping headers - if we ever want to put it on CPAN
# this Makefile will need to change first - see one of the other contrib
# Makefile.PL files for a template.
#

WriteMakefile(
    NAME		=> 'Sun::Solaris::Intrs',
    VERSION_FROM	=> 'Intrs.pm',
    DEFINE		=> exists($ENV{RELEASE_BUILD}) ? '-DNDEBUG' : '',

    # ../../../../../../../uts/common can be removed when Perl leaves O/N

    # ../../../../../../../uts/common refers to 5.8.4 building in 5.8.4/contrib
    # whereas later versions build in $(VERSION)/

    # Must be a relative path to avoid being interpreted as a proto area path.
    INC			=> "-I../../../../../../../uts/common -I../../../../../../uts/common",
    MAN3PODS		=> {},
);
