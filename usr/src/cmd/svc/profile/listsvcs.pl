#!/usr/bin/perl
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# listsvcs [-e] profile ...
#
# List all service instances in an SMF profile.
# Options:
#	-e	List enabled instances only
#

use XML::Parser;
use Getopt::Std;
use strict;

my %opts;
my $servicename;	# name attribute of the enclosing service element
my @svcs = ();		# services list under construction

if (!getopts("e", \%opts)) {
	die "Usage: $0 [-e] profile ...\n";
}
my $list_all = !$opts{e};

my $parser = new XML::Parser;
$parser->setHandlers(Start => \&start_handler, End => \&end_handler);

for my $file (@ARGV) {
	$parser->parsefile($file);
}
print join("\n", sort(@svcs)), "\n";

sub start_handler
{
	my ($p, $el, %attrs) = @_;
	my $name;

	return unless ($attrs{"name"});
	$name = $attrs{"name"};

	if ($el eq "service") {
		$servicename = $name;
	} elsif ($el eq "instance" && defined $servicename) {
		push(@svcs, "$servicename:$name")
			if ($list_all || $attrs{"enabled"} eq "true");
	}
}

sub end_handler
{
	my ($p, $el) = @_;

	if ($el eq "service") {
		$servicename = undef;
	}
}
