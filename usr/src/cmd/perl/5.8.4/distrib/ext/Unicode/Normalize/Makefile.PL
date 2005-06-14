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
use ExtUtils::MakeMaker;

my $clean = {};

if (-f "Normalize.xs") {
    print STDERR "Making header files for XS...\n";

    do "mkheader";
    $clean = { FILES => 'unfcan.h unfcmb.h unfcmp.h unfcpt.h unfexc.h' };
}

WriteMakefile(
    'INSTALLDIRS'	=> $] >= 5.007 ? 'perl' : 'site',
    'NAME'		=> 'Unicode::Normalize',
    'VERSION_FROM'	=> 'Normalize.pm', # finds $VERSION
    'clean'		=> $clean,
);
