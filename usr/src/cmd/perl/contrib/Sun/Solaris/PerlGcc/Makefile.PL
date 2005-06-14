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
# Makefile.PL for ::PerlGcc
#

require 5.6.1;
use strict;
use warnings;
use ExtUtils::MakeMaker;

# Check we are on a supported OS version.
my ($os, $host, $rel, $ver, $arch, $isa, $plat) = split(' ', qx{uname -a});
my $hw = $arch;
$hw = 'x86' if ($hw eq 'i86pc');
$hw = 'sparc' if ($hw =~ /^sun4/);
my $pver = sprintf('%vd', $^V);

# Figure out the appropriate Config.pm
my $configpm = "config/$pver/$rel/$hw/Config.pm";
die("Unsupported Perl version/OS version/Architecture $pver/$rel/$hw\n")
    unless (-f $configpm);

our %man1pods;
# Only install the pods for onn-ON builds.
if (! exists($ENV{CODEMGR_WS}) && ! exists($ENV{ENVCPPFLAGS1})) {
	$man1pods{'pod/perlgcc.pod'} = '$(INST_MAN1DIR)/perlgcc.$(MAN1EXT)';
}

WriteMakefile(
    NAME         => 'Sun::Solaris::PerlGcc',
    VERSION_FROM => 'perlgcc.PL',
    PL_FILES     => { 'perlgcc.PL' => 'perlgcc' },
    EXE_FILES    => [ 'perlgcc' ],
    PM           => { $configpm => '$(INST_LIBDIR)/PerlGcc/Config.pm' },
    MAN1PODS     => \%man1pods,
    MAN3PODS     => { }, # Stop autopodification.
    clean        => { FILES => 'perlgcc' },
);
