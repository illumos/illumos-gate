#! /usr/perl5/bin/perl
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Generate README.opensolaris from a template for inclusion in a
# delivery wad.
# Usage: mkreadme_osol README.opensolaris < template
#

use strict;
use warnings;

#
# Timeout and retry settings for wget.  Allow one retry for the
# occasional glitch, but don't wait longer than 5 minutes (so as not
# to hold up the build).
#
my $timeout = 150;
my $tries = 2;

#
# Markers in the web pages that we download.
#
my $begin_data = qr/\[begin README tag - do not delete\]/;
my $end_data = qr/\[end README tag - do not delete\]/;

my $readme_fn = shift || die "missing README filepath\n";
open(README_OUT, ">$readme_fn") || die "couldn't open $readme_fn\n";
my @lines = <STDIN>;

my %content;

if (! $ENV{"HTTP_PROXY"}) {
	if ($ENV{"http_proxy"}) {
		$ENV{"HTTP_PROXY"} = $ENV{"http_proxy"};
	} else {
		$ENV{"HTTP_PROXY"} = "http://webcache.sfbay:8080";
	}
}
if (! $ENV{"http_proxy"}) {
	$ENV{"http_proxy"} = $ENV{"HTTP_PROXY"};
}

#
# Make a pass through the input file and download any web pages that
# are included by reference.
#
foreach (@lines) {
	chomp;
	if (/^<!-- #include (.+) -->$/) {
		my $url = $1;
		print "Getting $url\n";
		# Download the page into $content{$url}.
		$content{$url} =
		    `/usr/sfw/bin/wget -q -O - -T $timeout -t $tries $url`;
		if (! $content{$url}) {
			die "$url: invalid or empty URI.\n";
		}
		#
		# Clean up the downloaded contents: remove carriage
		# returns, strip out content that is outside the
		# delimiter tags, convert HTML-encoded characters back
		# into plain text.
		#
		$content{$url} =~ s/\r//g;
		my @c = split /\n/, $content{$url};
		my $l;
		# Work forwards to find start.
		while (defined ($l = shift @c)) {
			if ($l =~ /$begin_data/) {
				last;
			}
		}
		if (! defined $l) {
			print "Warning: content start delimiter not found\n";
		} else {
			# Work backwards to find end.
			while (defined ($l = pop @c)) {
				if ($l =~ /$end_data/) {
					last;
				}
			}
			if (! defined $l) {
				print "Warning: content end delimiter ",
				    "not found\n";
			}
		}
		$content{$url} = join "\n", @c;
		$content{$url} =~ s/&amp;/&/g;
		$content{$url} =~ s/&lt;/</g;
		$content{$url} =~ s/&#60;/</g;
		$content{$url} =~ s/&gt;/>/g;
		$content{$url} =~ s/&#62;/>/g;
	}
}

#
# Make a second pass through the input file.  Pass most text on
# verbatim; replace #include directives with the content that was
# downloaded by the previous pass.
#
foreach (@lines) {
	if (/^<!-- #include (.+) -->$/ && exists($content{$1})) {
		print README_OUT $content{$1};
	} else {
		print README_OUT "$_\n";
	}
}

print README_OUT "\n\n";
close(README_OUT);
