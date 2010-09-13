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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

use ExtUtils::MakeMaker;
my ($defines, $includes) = ('', '');

# Uncomment this to turn on assertions
#$defines .= '-DKSTAT_DEBUG ';

# Uncomment this to report unknown binary kstats
#$defines .= '-DREPORT_UNKNOWN ';

#
# Because there are still platform specific raw kstats, we need to include the
# platform specific header files, so work out where they live.
#
my $arch = qx{uname -p}; chomp($arch);
if ($arch eq 'sparc') {
	$includes .= '-I/usr/platform/sun4u/include' .
	    ' -I/usr/platform/sun4v/include';
} elsif ($arch eq 'i386') {
	$includes .= '-I/usr/platform/i86pc/include' .
	    ' -I/usr/platform/i86xpv/include';
} else {
	die("Unknown architecture $arch\n");
}

WriteMakefile(
    NAME         => 'Sun::Solaris::Kstat',
    VERSION_FROM => 'Kstat.pm',
    LIBS         => [ '-lkstat' ],
    DEFINE       => $defines,
    INC          => $includes,
    OBJECT       => '$(O_FILES)',
);
