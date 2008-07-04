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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# lgrpinfo: display information about locality groups.
#

require 5.6.1;
use warnings;
use strict;
use Getopt::Long qw(:config no_ignore_case bundling auto_version);
use File::Basename;
# Sun::Solaris::Kstat is used to extract per-lgroup load average.
use Sun::Solaris::Kstat;
use POSIX qw(locale_h);
use Sun::Solaris::Utils qw(textdomain gettext);
use Sun::Solaris::Lgrp ':CONSTANTS';

use constant KB => 1024;

#
# Amount of load contributed by a single thread. The value is exported by the
# kernel in the 'loadscale' variable of lgroup kstat, but in case it is missing
# we use the current default value as the best guess.
#
use constant LGRP_LOADAVG_THREAD_MAX => 65516;

# Get script name
our $cmdname = basename($0, ".pl");

# Get liblgrp version
my $version = Sun::Solaris::Lgrp::lgrp_version();

our $VERSION = "%I% (liblgrp version $version)";

# The $loads hash keeps per-lgroup load average.
our $loads = {};

########################################
# Main body
##

# Set message locale
setlocale(LC_ALL, "");
textdomain(TEXT_DOMAIN);

# Parse command-line options
our($opt_a, $opt_l, $opt_m, $opt_c, $opt_C, $opt_e, $opt_t, $opt_h, $opt_u,
    $opt_r, $opt_L, $opt_P, $opt_I, $opt_T, $opt_G);

GetOptions("a"   => \$opt_a,
	   "c"   => \$opt_c,
	   "C"	 => \$opt_C,
	   "e"	 => \$opt_e,
	   "G"	 => \$opt_G,
	   "h|?" => \$opt_h,
	   "l"   => \$opt_l,
	   "L"	 => \$opt_L,
	   "I"   => \$opt_I,
	   "m"   => \$opt_m,
	   "r"   => \$opt_r,
	   "t"	 => \$opt_t,
	   "T"   => \$opt_T,
	   "u=s" => \$opt_u,
	   "P"   => \$opt_P) || usage(3);

usage(0) if $opt_h;

# Check for conflicting options
my $nfilters = 0;
$nfilters++ if $opt_C;
$nfilters++ if $opt_P;
$nfilters++ if $opt_T;

if ($nfilters > 1) {
	printf STDERR
	  gettext("%s: Options -C, -T and -P can not be used together\n"),
	    $cmdname;
	usage(3);
}

if ($opt_T && ($opt_I || $opt_t)) {
	printf STDERR
	  gettext("%s: Option -T can not be used with -I, -t\n"),
	    $cmdname;
	usage(3);
}

if ($opt_T && scalar @ARGV) {
	printf STDERR
	  gettext("%s: Warning: with '-T' all lgroups on the command line "),
	    $cmdname;
	printf STDERR gettext("are ignored\n\n");
}

if ($opt_L && $opt_I) {
	printf STDERR gettext("%s: Option -I can not be used with -L\n"),
	  $cmdname;
	usage(3);
}

# Figure out what to do based on options
my $do_default = 1 unless
  $opt_a || $opt_l || $opt_m || $opt_c || $opt_e || $opt_t || $opt_r;


my $l =  Sun::Solaris::Lgrp->new($opt_G ? LGRP_VIEW_OS : LGRP_VIEW_CALLER) or
    die(gettext("$cmdname: can not get lgroup information from the system\n"));


# Get list of all lgroups, the root and the list of intermediates
my @lgrps = nsort($l->lgrps);
my $root = $l->root;
my @intermediates = grep { $_ != $root && !$l->isleaf($_) } @lgrps;
my $is_uma = (scalar @lgrps == 1);

# Print everything if -a is specified or it is default without -T
my $do_all    = 1 if $opt_a  || ($do_default && !($opt_T || $opt_L));

# Print individual information if do_all or requested specific print
my $do_lat    = 1 if $do_all || $opt_l;
my $do_memory = 1 if $do_all || $opt_m;
my $do_cpu    = 1 if $do_all || $opt_c;
my $do_topo   = 1 if $do_all || $opt_t;
my $do_rsrc   = 1 if $do_all || $opt_r;
my $do_load   = 1 if $do_all || $opt_e;
my $do_table  = 1 if $opt_a  || $opt_L;
my $do_something = ($do_lat || $do_memory || $do_cpu || $do_topo ||
		    $do_rsrc || $do_load);

# Does the liblgrp(3LIB) has enough capabilities to support resource view?
if ($do_rsrc && LGRP_VER_CURRENT == 1) {
	if ($opt_r) {
		printf STDERR
		  gettext("%s: sorry, your system does not support"),
		    $cmdname;
		printf STDERR " lgrp_resources(3LGRP)\n";
	}
	$do_rsrc = 0;
}

# Get list of lgrps from arguments, expanding symbolic names like
# "root" and "leaves"
# Use all lgroups if none are specified on the command line
my @lgrp_list = (scalar (@ARGV) && !$opt_T) ? lgrp_expand($l, @ARGV) : @lgrps;

# Apply 'Parent' or 'Children' operations if requested
@lgrp_list = map { $l->parents($_)  } @lgrp_list if $opt_P;
@lgrp_list = map { $l->children($_) } @lgrp_list if $opt_C;

# Drop repeating elements and sort lgroups numerically.
@lgrp_list = uniqsort(@lgrp_list);

# If both -L and -c are specified, just print list of CPUs.
if ($opt_c && $opt_I) {
	my @cpus = uniqsort(map { $l->cpus($_, LGRP_CONTENT_HIERARCHY) }
			    @lgrp_list);
	print "@cpus\n";
	exit(0);
}

my $unit_str = "K";
my $units = KB;

# Convert units to canonical numeric and string formats.
if ($opt_u) {
	if ($opt_u =~ /^b$/i) {
		$units = 1;
		$unit_str = "B";
	} elsif ($opt_u =~ /^k$/i) {
		$units = KB;
		$unit_str = "K";
	} elsif ($opt_u =~ /^m$/i) {
		$units = KB * KB;
		$unit_str = "M";
	} elsif ($opt_u =~ /^g$/i) {
		$units = KB * KB * KB;
		$unit_str = "G";
	} elsif ($opt_u =~ /^t$/i) {
		$units = KB * KB * KB * KB;
		$unit_str = "T";
	} elsif ($opt_u =~ /^p$/i) {
		$units = KB * KB * KB * KB * KB;
		$unit_str = "P";
	} elsif ($opt_u =~ /^e$/i) {
		$units = KB * KB * KB * KB * KB * KB;
		$unit_str = "E";
	} elsif (! ($opt_u =~ /^m$/i)) {
		printf STDERR
		  gettext("%s: invalid unit '$opt_u', should be [b|k|m|g|t|p|e]"),
		    $cmdname;
		printf STDERR gettext(", using the default.\n\n");
		$opt_u = 0;
	}
}

# Collect load average data if requested.
$loads = get_lav() if $do_load;

# Get latency values for each lgroup.
my %self_latencies;
map { $self_latencies{$_} = $l->latency($_, $_) } @lgrps;

# If -T is specified, just print topology and return.
if ($opt_T) {
	lgrp_prettyprint($l);
	print_latency_table(\@lgrps, \@lgrps) if $do_table;
	exit(0);
}

if (!scalar @lgrp_list) {
	printf STDERR gettext("%s: No matching lgroups found!\n"), $cmdname;
	exit(2);
}

# Just print list of lgrps if doing just filtering
(print "@lgrp_list\n"), exit 0 if $opt_I;

if ($do_something) {
	# Walk through each requested lgrp and print whatever is requested.
	foreach my $lgrp (@lgrp_list) {
		my $is_leaf = $l->isleaf($lgrp);
		my ($children, $parents, $cpus, $memstr, $rsrc);

		my $prefix = ($lgrp == $root) ?
		  "root": $is_leaf ? gettext("leaf") : gettext("intermediate");
		printf gettext("lgroup %d (%s):"), $lgrp, $prefix;

		if ($do_topo) {
			# Get children of this lgrp.
			my @children = $l->children($lgrp);
			$children = $is_leaf ?
			  gettext("Children: none") :
			    gettext("Children: ") . lgrp_collapse(@children);
			# Are there any parents for this lgrp?
			my @parents = $l->parents($lgrp);
			$parents = @parents ?
			  gettext(", Parent: ") . "@parents" :
			    "";
		}

		if ($do_cpu) {
			$cpus = lgrp_showcpus($lgrp, LGRP_CONTENT_HIERARCHY);
		}
		if ($do_memory) {
			$memstr = lgrp_showmemory($lgrp, LGRP_CONTENT_HIERARCHY);
		}
		if ($do_rsrc) {
			$rsrc = lgrp_showresources($lgrp);
		}

		# Print all the information about lgrp.
		print "\n\t$children$parents"	if $do_topo;
		print "\n\t$cpus"		if $do_cpu && $cpus;
		print "\n\t$memstr"		if $do_memory && $memstr;
		print "\n\t$rsrc"		if $do_rsrc;
		print "\n\t$loads->{$lgrp}"	if defined ($loads->{$lgrp});
		if ($do_lat && defined($self_latencies{$lgrp})) {
		    printf gettext("\n\tLatency: %d"), $self_latencies{$lgrp};
		}
		print "\n";
	}
}

print_latency_table(\@lgrps, \@lgrp_list) if $do_table;

exit 0;

#
# usage(exit_status)
# print usage message and exit with the specified exit status.
#
sub usage
{
	printf STDERR gettext("Usage:\t%s"), $cmdname;
	print STDERR " [-aceGlLmrt] [-u unit] [-C|-P] [lgrp] ...\n";
	print STDERR "      \t$cmdname -I [-c] [-G] [-C|-P] [lgrp] ...\n";
	print STDERR "      \t$cmdname -T [-aceGlLmr] [-u unit]\n";
	print STDERR "      \t$cmdname -h\n\n";

	printf STDERR
	  gettext("   Display information about locality groups\n\n" .
		  "\t-a: Equivalent to \"%s\" without -T and to \"%s\" with -T\n"),
		    "-celLmrt", "-celLmr";

	print STDERR
	  gettext("\t-c: Print CPU information\n"),
	  gettext("\t-C: Children of the specified lgroups\n"),
	  gettext("\t-e: Print lgroup load average\n"),
	  gettext("\t-h: Print this message and exit\n"),
	  gettext("\t-I: Print lgroup or CPU IDs only\n"),
	  gettext("\t-l: Print information about lgroup latencies\n"),
	  gettext("\t-G: Print OS view of lgroup hierarchy\n"),
	  gettext("\t-L: Print lgroup latency table\n"),
	  gettext("\t-m: Print memory information\n"),
	  gettext("\t-P: Parent(s) of the specified lgroups\n"),
	  gettext("\t-r: Print lgroup resources\n"),
	  gettext("\t-t: Print information about lgroup topology\n"),
	  gettext("\t-T: Print the hierarchy tree\n"),
	  gettext("\t-u unit: Specify memory unit (b,k,m,g,t,p,e)\n\n\n");

	print STDERR
	  gettext("    The lgrp may be specified as an lgroup ID,"),
	  gettext(" \"root\", \"all\",\n"),
	  gettext("    \"intermediate\" or \"leaves\".\n\n");

	printf STDERR
	  gettext("    The default set of options is \"%s\"\n\n"),
	    "-celmrt all";

	print STDERR
	  gettext("    Without any options print topology, CPU and memory " .
		  "information about each\n" .
		  "    lgroup. If any lgroup IDs are specified on the " .
		  "command line only print\n" .
		  "    information about the specified lgroup.\n\n");

	exit(shift);
}

# Return the input list with duplicates removed.
sub uniq
{
	my %seen;
	return (grep { ++$seen{$_} == 1 } @_);
}

#
# Sort the list numerically
# Should be called in list context
#
sub nsort
{
	return (sort { $a <=> $b } @_);
}

#
# Sort list numerically and remove duplicates
# Should be called in list context
#
sub uniqsort
{
	return (sort { $a <=> $b } uniq(@_));
}

# Round values
sub round
{
	my $val = shift;

	return (int($val + 0.5));
}

#
# Expand list of lgrps.
# 	Translate 'root' to the root lgrp id
# 	Translate 'all' to the list of all lgrps
# 	Translate 'leaves' to the list of all lgrps'
#	Translate 'intermediate' to the list of intermediates.
#
sub lgrp_expand
{
	my $lobj = shift;
	my %seen;
	my @result;

	# create a hash element for every element in @lgrps
	map { $seen{$_}++ } @lgrps;

	foreach my $lgrp (@_) {
		push(@result, $lobj->root),   next if $lgrp =~ m/^root$/i;
		push(@result, @lgrps),	      next if $lgrp =~ m/^all$/i;
		push(@result, $lobj->leaves), next if $lgrp =~ m/^leaves$/i;
		push(@result, @intermediates),
		  next if $lgrp =~ m/^intermediate$/i;
		push(@result, $lgrp),
		  next if $lgrp =~ m/^\d+$/ && $seen{$lgrp};
		printf STDERR gettext("%s: skipping invalid lgrp $lgrp\n"),
		  $cmdname;
	}

	return @result;
}

#
# lgrp_tree(class, node)
#
# Build the tree of the lgroup hierarchy starting with the specified node or
# root if no initial node is specified. Calls itself recursively specifying each
# of the children as a starting node. Builds a reference to the list with the
# node in the end and each element being a subtree.
#
sub lgrp_tree
{
	my $c = shift;
	my $lgrp = shift || $c->root;

	# Call itself for each of the children and combine results in a list.
	[ (map { lgrp_tree($c, $_) } $c->children($lgrp)), $lgrp ];
}

#
# lgrp_pp(tree, prefix, childprefix, npeers)
#
# pretty-print the hierarchy tree.
# Input Arguments:
#	Reference to the tree
#	Prefix for me to use
#	Prefix for my children to use
#	Number of peers left
#
sub lgrp_pp
{
	my $tree = shift;
	my $myprefix = shift;
	my $childprefix = shift;
	my $npeers = shift;
	my $el = pop @$tree;
	my $nchildren = scalar @$tree;
	my $printprefix = "$childprefix";
	my $printpostfix = $npeers ? "|   " : "    ";

	return unless defined ($el);

	my $bar = $npeers ? "|" : "`";
	print $childprefix ? $childprefix : "";
	print $myprefix ? "$bar" . "-- " : "";
	lgrp_print($el, "$printprefix$printpostfix");

	my $new_prefix = $npeers ? $myprefix : "    ";

	# Pretty-print the subtree with a new offset.
	map {
		lgrp_pp($_, "|   ", "$childprefix$new_prefix", --$nchildren)
	} @$tree;
}

# Pretty print the whole tree
sub lgrp_prettyprint
{
	my $c = shift;
	my $tree = lgrp_tree $c;
	lgrp_pp($tree, '', '', scalar $tree - 1);
}

sub lgrp_print
{
	my $lgrp = shift;
	my $prefix = shift;
	my ($cpus, $memstr, $rsrc);
	my $is_interm = ($lgrp != $root && !$l->isleaf($lgrp));
	my $not_root = $is_uma || $lgrp != $root;

	print "$lgrp";

	if ($do_cpu && $not_root) {
		$cpus   = lgrp_showcpus($lgrp, LGRP_CONTENT_HIERARCHY);
	}
	if ($do_memory && $not_root) {
		$memstr = lgrp_showmemory($lgrp, LGRP_CONTENT_HIERARCHY);
	}
	if ($do_rsrc && ($is_uma || $is_interm)) {
		$rsrc   = lgrp_showresources($lgrp) if $do_rsrc;
	}

	# Print all the information about lgrp.

	print "\n$prefix$cpus"		if $cpus;
	print "\n$prefix$memstr"	if $memstr;
	print "\n$prefix$rsrc"		if $rsrc;
	print "\n$prefix$loads->{$lgrp}"	if defined ($loads->{$lgrp});

	# Print latency information if requested.
	if ($do_lat && $lgrp != $root && defined($self_latencies{$lgrp})) {
		print "\n${prefix}";
		printf gettext("Latency: %d"), $self_latencies{$lgrp};
	}
	print "\n";
}

# What CPUs are in this lgrp?
sub lgrp_showcpus
{
	my $lgrp = shift;
	my $hier = shift;

	my @cpus = $l->cpus($lgrp, $hier);
	my $ncpus = @cpus;
	return 0 unless $ncpus;
	# Sort CPU list if there is something to sort.
	@cpus = nsort(@cpus) if ($ncpus > 1);
	my $cpu_string = lgrp_collapse(@cpus);
	return (($ncpus == 1) ?
		gettext("CPU: ") . $cpu_string:
		gettext("CPUs: ") . $cpu_string);
}

# How much memory does this lgrp contain?
sub lgrp_showmemory
{
	my $lgrp = shift;
	my $hier = shift;

	my $memory = $l->mem_size($lgrp, LGRP_MEM_SZ_INSTALLED, $hier);
	return (0) unless $memory;
	my $freemem = $l->mem_size($lgrp, LGRP_MEM_SZ_FREE, $hier) || 0;

	my $memory_r = memory_to_string($memory);
	my $freemem_r = memory_to_string($freemem);
	my $usedmem = memory_to_string($memory - $freemem);

	my $memstr = sprintf(gettext("Memory: installed %s"),
			     $memory_r);
	$memstr = $memstr . sprintf(gettext(", allocated %s"),
				    $usedmem);
	$memstr = $memstr . sprintf(gettext(", free %s"),
				    $freemem_r);
	return ($memstr);
}

# Get string containing lgroup resources
sub lgrp_showresources
{
	my $lgrp = shift;
	my $rsrc_prefix = gettext("Lgroup resources:");
	# What resources does this lgroup contain?
	my @resources_cpu = nsort($l->resources($lgrp, LGRP_RSRC_CPU));
	my @resources_mem = nsort($l->resources($lgrp, LGRP_RSRC_MEM));
	my $rsrc = @resources_cpu || @resources_mem ? "" : gettext("none");
	$rsrc = $rsrc_prefix . $rsrc;
	my $rsrc_cpu = lgrp_collapse(@resources_cpu);
	my $rsrc_mem = lgrp_collapse(@resources_mem);
	my $lcpu = gettext("CPU");
	my $lmemory = gettext("memory");
	$rsrc = "$rsrc $rsrc_cpu ($lcpu);" if scalar @resources_cpu;
	$rsrc = "$rsrc $rsrc_mem ($lmemory)" if scalar @resources_mem;
	return ($rsrc);
}

#
# Consolidate consequtive ids as start-end
# Input: list of ids
# Output: string with space-sepated cpu values with ranges
#   collapsed as x-y
#
sub lgrp_collapse
{
	return ('') unless @_;
	my @args = uniqsort(@_);
	my $start = shift(@args);
	my $result = '';
	my $end = $start;	# Initial range consists of the first element
	foreach my $el (@args) {
		if ($el == ($end + 1)) {
			#
			# Got consecutive ID, so extend end of range without
			# printing anything since the range may extend further
			#
			$end = $el;
		} else {
			#
			# Next ID is not consecutive, so print IDs gotten so
			# far.
			#
			if ($end > $start + 1) {	# range
				$result = "$result $start-$end";
			} elsif ($end > $start) {	# different values
				$result = "$result $start $end";
			} else {	# same value
				$result = "$result $start";
			}

			# Try finding consecutive range starting from this ID
			$start = $end = $el;
		}
	}

	# Print last ID(s)
	if ($end > $start + 1) {
		$result = "$result $start-$end";
	} elsif ($end > $start) {
		$result = "$result $start $end";
	} else {
		$result = "$result $start";
	}
	# Remove any spaces in the beginning
	$result =~ s/^\s+//;
	return ($result);
}

# Print latency information if requested and the system has several lgroups.
sub print_latency_table
{
	my ($lgrps1, $lgrps2) = @_;

	return unless scalar @lgrps;

	# Find maximum lgroup
	my $max = $root;
	map { $max = $_ if $max < $_ } @$lgrps1;

	# Field width for lgroup - the width of the largest lgroup and 1 space
	my $lgwidth = length($max) + 1;
	# Field width for latency. Get the maximum latency and add 1 space.
	my $width = length($l->latency($root, $root)) + 1;
	# Make sure that width is enough to print lgroup itself.
	$width = $lgwidth if $width < $lgwidth;

	# Print table header
	print gettext("\nLgroup latencies:\n");
	# Print horizontal line
	print "\n", "-" x ($lgwidth + 1);
	map { print '-' x $width } @$lgrps1;
	print "\n", " " x $lgwidth, "|";
	map { printf("%${width}d", $_) } @$lgrps1;
	print "\n", "-" x ($lgwidth + 1);
	map { print '-' x $width } @$lgrps1;
	print "\n";

	# Print the latency table
	foreach my $l1 (@$lgrps2) {
		printf "%-${lgwidth}d|", $l1;
		foreach my $l2 (@lgrps) {
			my $latency = $l->latency($l1, $l2);
			if (!defined ($latency)) {
				printf "%${width}s", "-";
			} else {
				printf "%${width}d", $latency;
			}
		}
		print "\n";
	}

	# Print table footer
	print "-" x ($lgwidth + 1);
	map { print '-' x $width } @lgrps;
	print "\n";
}

#
# Convert a number to a string representation
# The number is scaled down until it is small enough to be in a good
# human readable format i.e. in the range 0 thru 1023.
# If it's smaller than 10 there's room enough to provide one decimal place.
#
sub number_to_scaled_string
{
	my $number = shift;

	my $scale = KB;
	my @measurement = ('K', 'M', 'G', 'T', 'P', 'E');	# Measurement
	my $uom = shift(@measurement);
	my $result;

	my $save = $number;

	# Get size in K.
	$number /= KB;

	while (($number >= $scale) && $uom ne 'E') {
		$uom = shift(@measurement);
		$save = $number;
		$number /= $scale;
	}

	# check if we should output a decimal place after the point
	if ($save && (($save / $scale) < 10)) {
		$result = sprintf("%2.1f", $save / $scale);
	} else {
		$result = round($number);
	}
	return ("$result$uom");
}

#
# Convert memory size to the string representation
#
sub memory_to_string
{
	my $number = shift;

	# Zero memory - just print 0
	return ("0$unit_str") unless $number;

	#
	# Return memory size scaled to human-readable form unless -u is
	# specified.
	#
	return (number_to_scaled_string($number)) unless $opt_u;

	my $scaled = $number / $units;
	my $result;

	if ($scaled < 0.1) {
		$result = sprintf("%2.1g", $scaled);
	} elsif ($scaled < 10) {
		$result = sprintf("%2.1f", $scaled);
	} else {
		$result = int($scaled + 0.5);
	}
	return ("$result$unit_str");
}

#
# Read load averages from lgrp kstats Return hash reference indexed by lgroup ID
# for each lgroup which has load information.
#
sub get_lav
{
	my $load = {};

	my $ks = Sun::Solaris::Kstat->new(strip_strings => 1) or
	  warn(gettext("$cmdname: kstat_open() failed: %!\n")),
	    return $load;

	my $lgrp_kstats = $ks->{lgrp} or
	  warn(gettext("$cmdname: can not read lgrp kstat\n)")),
	    return $load;

	# Collect load for each lgroup
	foreach my $i (keys %$lgrp_kstats) {
		next unless $lgrp_kstats->{$i}->{"lgrp$i"};
		my $lav = $lgrp_kstats->{$i}->{"lgrp$i"}->{"load average"};
		# Skip this lgroup if can't find its load average
		next unless defined $lav;
		my $scale = $lgrp_kstats->{$i}->{"lgrp$i"}->{"loadscale"} ||
			LGRP_LOADAVG_THREAD_MAX;
		$load->{$i} = sprintf (gettext("Load: %4.3g"), $lav / $scale);
	}
	return $load;
}
