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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/perl/contrib/Sun/Solaris/Kstat/Makefile.PL
#

use ExtUtils::MakeMaker;
my ($def, $inc) = ('', '');

#$def .= '-DKSTAT_DEBUG ';	# Uncomment this to turn on assertions
#$def .= '-DREPORT_UNKNOWN ';	# Uncomment this to report unknown binary kstats

#
# Because there are still platform specific raw kstats, we need to include the
# platform specific header files, so work out where they live.
#
my $plat_dir = qx{uname -m}; chomp($plat_dir);
$plat_dir = 'sun4u' if ($plat =~ /^sun4/);
$plat_dir = "-I/usr/platform/$plat_dir/include";

WriteMakefile(
    NAME         => 'Sun::Solaris::Kstat',
    VERSION_FROM => 'Kstat.pm',
    LIBS         => [ '-lkstat' ],
    INC          => $plat_dir,
    OBJECT       => '$(O_FILES)',
    DEFINE       => $def,
);
