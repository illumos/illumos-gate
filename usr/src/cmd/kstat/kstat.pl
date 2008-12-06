#!/usr/perl5/bin/perl
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
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

require 5.8.4;
use strict;
use warnings;
use locale;
use Getopt::Std;
use POSIX qw(locale_h ctime);
use File::Basename;
use Sun::Solaris::Utils qw(textdomain gettext gmatch);
use Sun::Solaris::Kstat;

#
# Print an usage message and exit
#

sub usage(@)
{
	my (@msg) = @_;
	print STDERR basename($0), ": @msg\n" if (@msg);
	print STDERR gettext(
	"Usage:\n" .
	"kstat [ -qlp ] [ -T d|u ] [ -c class ]\n" .
	"      [ -m module ] [ -i instance ] [ -n name ] [ -s statistic ]\n" .
	"      [ interval [ count ] ]\n" .
	"kstat [ -qlp ] [ -T d|u ] [ -c class ]\n" .
	"      [ module:instance:name:statistic ... ]\n" .
	"      [ interval [ count ] ]\n"
	);
	exit(2);
}

#
# Print a fatal error message and exit
#

sub error(@)
{
	my (@msg) = @_;
	print STDERR basename($0), ": @msg\n" if (@msg);
	exit(1);
}

#
# Generate an anonymous sub that can be used to filter the kstats we will
# display.  The generated sub will take one parameter, the string to match
# against.  There are three types of input catered for:
#    1)  Empty string.  The returned sub will match anything
#    2)  String surrounded by '/' characters.  This will be interpreted as a 
#        perl RE.  If the RE is syntactically incorrect, an error will be
#        reported.
#    3) Any other string.  The returned sub will use gmatch(3GEN) to match
#       against the passed string
#

sub gen_sub($)
{
	my ($pat) = @_;

	# Anything undefined or empty will always match
	if (! defined($pat) || $pat eq '') {
		return (sub { 1; });

	# Anything surrounded by '/' is a perl RE
	} elsif ($pat =~ m!^/[^/]*/$!) {
		my $sub;
		if (! ($sub = eval "sub { return(\$_[0] =~ $pat); }" )) {
			$@ =~ s/\s+at\s+.*\n$//;
			usage($@);
		}
		return ($sub);

	# Otherwise default to gmatch
	} else {
		return (sub { return(gmatch($_[0], $pat)); });
	}
}

#
# Main routine of the script
#

# Set message locale
setlocale(LC_ALL, "");
textdomain(TEXT_DOMAIN);

# Process command options
my (%opt, @matcher);
getopts('?qlpT:m:i:n:s:c:', \%opt) || usage();
usage() if exists($opt{'?'});

# Validate -q and -l flags
my $quiet = exists($opt{q}) ? 1 : 0;
my $list = exists($opt{l}) ? 1 : 0;
my $parseable = exists($opt{'p'}) || $list ? 1 : 0;
usage(gettext("-q and -l are mutually exclusive")) if ($quiet && $list);

# Get interval & count if specified
my ($interval, $count) = (0, 1);
if (@ARGV >= 2 && $ARGV[-2] =~ /^\d+$/ && $ARGV[-1] =~ /^\d+$/) {
	$count = pop(@ARGV);
	$interval = pop(@ARGV);
	usage(gettext("Interval must be an integer >= 1")) if ($interval < 1);
	usage(gettext("Count must be an integer >= 1")) if ($count < 1);
} elsif (@ARGV >= 1 && $ARGV[-1] =~ /^\d+$/) {
	$interval = pop(@ARGV);
	$count = -1;
	usage(gettext("Interval must be an integer >= 1")) if ($interval < 1);
}

# Get timestamp flag
my $timestamp;
if ($timestamp = $opt{T}) {
	if ($timestamp eq "d") {
		$timestamp = sub { print(ctime(time())); };
	} elsif ($timestamp eq "u") {
		$timestamp = sub { print(time(), "\n"); };
	} else {
		usage(gettext("Invalid timestamp specifier"), $timestamp);
	}
}

# Deal with -[mins] flags
if (grep(/[mins]/, keys(%opt))) {
	usage(gettext("module:instance:name:statistic and " .
	    "-m -i -n -s are mutually exclusive")) if (@ARGV);
	push(@ARGV, join(":", map(exists($opt{$_}) ? $opt{$_} : "",
	    qw(m i n s))));
}

# Deal with class, if specified
my $class = gen_sub(exists($opt{c}) ? $opt{c} : '');

# If no selectors have been defined, add a dummy one to match everything
push(@ARGV, ":::") if (! @ARGV);

# Convert each remaining option into four anonymous subs
foreach my $p (@ARGV) {
	push(@matcher, [ map(gen_sub($_), (split(/:/, $p, 4))[0..3]) ]);
}

# Loop, printing the selected kstats as many times and as often as required
my $ks = Sun::Solaris::Kstat->new(strip_strings => 1);
my $matched = 0;

# Format strings for displaying data
my $fmt1 = "module: %-30.30s  instance: %-6d\n";
my $fmt2 = "name:   %-30.30s  class:    %-.30s\n";
my $fmt3 = "\t%-30s  %s\n";

while ($count == -1 || $count-- > 0) {
	&$timestamp() if ($timestamp);

	foreach my $m (@matcher) {
		my ($module, $instance, $name, $statistic) = @$m;

		foreach my $m (sort(grep(&$module($_), keys(%$ks)))) {
			my $mh = $ks->{$m};

			foreach my $i (sort({ $a <=> $b }
			    grep(&$instance($_), keys(%$mh)))) {
				my $ih = $mh->{$i};

				foreach my $n (sort(grep(&$name($_),
				    keys(%$ih)))) {
					my $nh = $ih->{$n};

					# Prune any not in the required class
					next if (! &$class($nh->{class}));

					if ($quiet) {
						$matched = grep(&$statistic($_),
						    keys(%$nh)) ? 1 : 0;

					} elsif ($parseable) {
						foreach my $s
						    (sort(grep(&$statistic($_),
						    keys(%$nh)))) {
							print("$m:$i:$n:$s");
							print("\t$nh->{$s}")
							    if (! $list);
							print("\n");
							$matched = 1;
						}

					# human-readable
					} else {
						if (my @stats =
						    sort(grep(&$statistic($_),
						    keys(%$nh)))) {
							printf($fmt1, $m, $i);
							printf($fmt2, $n,
							$nh->{class});
							foreach my $s
							    (grep($_ ne "class",
							    @stats)) {
								printf($fmt3,
								$s, $nh->{$s});
							}
							print("\n");
							$matched = 1;
						}
					}
				}
			}
		}
	}
	# Toggle line buffering off/on to flush output
	$| = 1; $| = 0;

	if ($interval && $count) {
		sleep($interval);
		$ks->update();
		print("\n");
	}
}
exit($matched ? 0 : 1);
