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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

require 5.8.4;
use strict;
use warnings;
use ExtUtils::MakeMaker;

#
# Compare OS versions.
#
sub cmp_os_ver
{
	our ($a, $b);
	my @v1 = split(/\./, $a);
	my @v2 = split(/\./, $b);
	my $diff = 0;
	while (@v1 || @v2) {
		last if (($diff = shift(@v1) - shift(@v2)) != 0);
	}
	return ($diff);
}

# Check we are on a supported OS version.
my $rel = qx{uname -r}; chomp($rel);
my $arch = qx{uname -p}; chomp($arch);
my $pver = sprintf('%vd', $^V);

# Figure out the appropriate Config.pm.  Use an older version if necessary.
my $configpm = "config/$pver/$rel/$arch/Config.pm";
if (! -f $configpm) {
	my $p = "config/$pver";
	my $dh;
	opendir($dh, $p) || die("Can't read directory $_: $!\n");
	my $old_rel = (sort(cmp_os_ver
	    grep(-d "$p/$_" && $_ =~ /^\d[\d.]+\d$/, readdir($dh))))[-1];
	closedir($dh);
	if (defined($old_rel)) {
		print(STDERR "Warning: No config file for OS version $rel, " .
		    "using $old_rel file\n");
		$rel = $old_rel;
		$configpm = "config/$pver/$rel/$arch/Config.pm";
	} else {
		die("Unsupported version of Perl/OS/Architecture " .
		    "$pver/$rel/$arch\n");
	}
}

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
