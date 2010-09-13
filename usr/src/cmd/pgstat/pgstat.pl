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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# pgstat - tool for displaying Processor Group statistics
#

use warnings;
use strict;
use File::Basename;
use List::Util qw(first max min);
use Errno;
use POSIX qw(locale_h strftime);
use Getopt::Long qw(:config no_ignore_case bundling auto_version);
use Sun::Solaris::Utils qw(textdomain gettext);
use Sun::Solaris::Pg;

#
# Constants section
#
# It is possible that wnen trying to parse PG kstats, PG generation changes
# which will cause PG new method to fail with errno set to EAGAIN In this case
# we retry open up to RETRY_COUNT times pausing RETRY_DELAY seconds between each
# retry.
#
# When printing PGs we print them as a little tree with each PG shifted by
# LEVEL_OFFSET from each parent. For example:
#
# PG  RELATIONSHIP                    CPUs
# 0   System                          0-7
# 3    Socket                         0 2 4 6
# 2     Cache                        0 2 4 6
#
#
# DEFAULT_INTERVAL - interval in seconds between snapshot if none is specified
# DEFAULT_COUNT	   - Number of iterations if none is specified
# HWLOAD_UNKNOWN   - Value that we use to represent unknown hardware load
# HWLOAD_UNDEF	   - Value that we use to represent undefined hardware load
#
use constant {
	VERSION		=> 1.1,
	DEFAULT_INTERVAL => 1,
        DEFAULT_COUNT	=> 1,
	RETRY_COUNT	=> 4,
        RETRY_DELAY	=> 0.25,
	HWLOAD_UNKNOWN	=> -1,
	HWLOAD_UNDEF	=> -2,
	LEVEL_OFFSET	=> 1,
};

#
# Format for fields, showing percentage headers
#
my $pcnt_fmt = "%6s";
#
# Format for percentages field
#
my $pcnt = "%5.1f";

#
# Return codes
#
#     0    Successful completion.
#
#     1    An error occurred.
#
#     2    Invalid command-line options were specified.
#
use constant {
	E_SUCCESS => 0,
	E_ERROR => 1,
	E_USAGE => 2,
};

#
# Valid sort keys for -s and -S options
#
my @sort_keys = qw(pg hwload swload user sys idle depth breadth);

# Set message locale
setlocale(LC_ALL, "");
textdomain(TEXT_DOMAIN);

# Get script name for error messages
our $cmdname = basename($0, ".pl");

my @pg_list;		# -P pg,...	- PG arguments
my @cpu_list;		# -c cpu,...	- CPU arguments
my @sharing_filter_neg; # -R string,... - Prune PGs
my @sharing_filter;	# -r string,...	- Matching sharing names
my $do_aggregate;	# -A		- Show summary in the end
my $do_cpu_utilization; # -C		- Show per-CPU utilization
my $do_physical;	# -p		- Show physical relationships
my $do_timestamp;	# -T		- Print timestamp
my $do_usage;		# -h		- Show usage
my $do_version;		# -V		- Verbose output
my $show_top;		# -t		- show top N
my $sort_order_a;	# -S key	- Ascending sort order
my $sort_order_d;	# -s key	- Descending sort order
my $verbose;		# -v		- Verbose output;

$verbose = 0;

# Parse options from the command line
GetOptions("aggregate|A"	=> \$do_aggregate,
	   "cpus|c=s"		=> \@cpu_list,
	   "showcpu|C"		=> \$do_cpu_utilization,
	   "help|h|?"		=> \$do_usage,
	   "pgs|P=s"		=> \@pg_list,
	   "physical|p"		=> \$do_physical,
	   "relationship|r=s"	=> \@sharing_filter,
	   "norelationship|R=s" => \@sharing_filter_neg,
	   "sort|s=s"		=> \$sort_order_d,
	   "Sort|S=s"		=> \$sort_order_a,
	   "top|t=i"		=> \$show_top,
	   "timestamp|T=s"	=> \$do_timestamp,
	   "version|V"		=> \$do_version,
	   "verbose+"		=> \$verbose,
	   "v+"			=> \$verbose,
) || usage(E_USAGE);

# Print usage message when -h is given
usage(E_SUCCESS) if $do_usage;

if ($do_version) {
	printf gettext("%s version %s\n"), $cmdname, VERSION;
	exit(E_SUCCESS);
}

#
# Verify options
#
# -T should have either u or d argument
if (defined($do_timestamp) && !($do_timestamp eq 'u' || $do_timestamp eq 'd')) {
	printf STDERR gettext("%s: Invalid -T %s argument\n"),
	  $cmdname, $do_timestamp;
	usage(E_USAGE);
}

if ($sort_order_a && $sort_order_d) {
	printf STDERR gettext("%s: -S and -s flags can not be used together\n"),
	  $cmdname;
	usage(E_USAGE);
}

if (defined ($show_top) && $show_top <= 0) {
	printf STDERR gettext("%s: -t should specify positive integer\n"),
	  $cmdname;
	usage(E_USAGE);
}

#
# Figure out requested sorting of the output
# By default 'depth-first' is used
#
my $sort_key;
my $sort_reverse;

if (!($sort_order_a || $sort_order_d)) {
	$sort_key = 'depth';
	$sort_reverse = 1;
} else {
	$sort_key = $sort_order_d || $sort_order_a;
	$sort_reverse = defined($sort_order_d);
}

#
# Make sure sort key is valid
#
if (!list_match($sort_key, \@sort_keys, 1)) {
	printf STDERR gettext("%s: invalid sort key %s\n"),
	  $cmdname, $sort_key;
	usage(E_USAGE);
}

#
# Convert -[Rr] string1,string2,... into list (string1, string2, ...)
#
@sharing_filter = map { split /,/ } @sharing_filter;
@sharing_filter_neg = map { split /,/ } @sharing_filter_neg;

#
# We use two PG snapshot to compare utilization between them. One snapshot is
# kept behind another in time.
#
my $p = Sun::Solaris::Pg->new(-cpudata => $do_cpu_utilization,
			      -swload => 1,
			      -tags => $do_physical,
			      -retry => RETRY_COUNT,
			      -delay => RETRY_DELAY);

if (!$p) {
	printf STDERR
	  gettext("%s: can not obtain Processor Group information: $!\n"),
	    $cmdname;
	exit(E_ERROR);
}

my $p_initial = $p;
my $p_dup = Sun::Solaris::Pg->new(-cpudata => $do_cpu_utilization,
				  -swload => 1,
				  -tags => $do_physical,
				  -retry => RETRY_COUNT,
				  -delay => RETRY_DELAY);

if (!$p_dup) {
	printf STDERR
	  gettext("%s: can not obtain Processor Group information: $!\n"),
	    $cmdname;
	exit(E_ERROR);
}

#
# Get interval and count
#
my $count = DEFAULT_COUNT;
my $interval = DEFAULT_INTERVAL;

if (scalar @ARGV > 0) {
	$interval = shift @ARGV;
	if (scalar @ARGV > 0) {
		$count = $ARGV[0];
	} else {
		$count = 0;
	}
}

if (! ($interval=~ m/^\d+\.?\d*$/)) {
	printf STDERR
	  gettext("%s: Invalid interval %s - should be numeric\n"),
	    $cmdname, $interval;
	usage(E_USAGE);
}

if ($count && ! ($count=~ m/^\d+$/)) {
	printf STDERR
	  gettext("%s: Invalid count %s - should be numeric\n"),
	    $cmdname, $count;
	usage(E_USAGE);
}

my $infinite = 1 unless $count;

#
# Get list of all PGs
#
my @all_pgs = $p->all_depth_first();

#
# get list of all CPUs in the system by looking at the root PG cpus
#
my @all_cpus = $p->cpus($p->root());

# PGs to work with
my @pgs = @all_pgs;

my $rc = E_SUCCESS;

#
# Convert CPU and PG lists into proper Perl lists, converting things like
# 1-3,5 into (1, 2, 3, 5). Also convert 'all' into the list of all CPUs or PGs
#
@cpu_list =
  map { $_ eq 'all' ? @all_cpus : $_ }	# all -> (cpu1, cpu2, ...)
  map { split /,/ } @cpu_list;		# x,y -> (x, y)

@cpu_list = $p->expand(@cpu_list);	# 1-3 -> 1 2 3

# Same drill for PGs
@pg_list =
  map { $_ eq 'all' ? @all_pgs : $_ }
  map { split /,/ } @pg_list;

@pg_list = $p->expand(@pg_list);

#
# Convert CPU list to list of PGs
#
if (scalar @cpu_list) {

	#
	# Warn about any invalid CPU IDs in the arguments
	# @bad_cpus is a list of invalid CPU IDs
	#
	my @bad_cpus = $p->set_subtract(\@all_cpus, \@cpu_list);
	if (scalar @bad_cpus) {
		printf STDERR
		  gettext("%s: Invalid processor IDs %s\n"),
		    $cmdname, $p->id_collapse(@bad_cpus);
		$rc = E_ERROR;
	}

	#
	# Find all PGs which have at least some CPUs from @cpu_list
	#
	my @pgs_from_cpus = grep {
		my @cpus = $p->cpus($_);
		scalar($p->intersect(\@cpus, \@cpu_list));
	} @all_pgs;

	# Combine PGs from @pg_list (if any) with PGs we found
	@pg_list = (@pg_list, @pgs_from_cpus);
}

#
# If there are any PGs specified by the user, complain about invalid ones
#
@pgs = get_pg_list($p, \@pg_list, \@sharing_filter, \@sharing_filter_neg);

if (scalar @pg_list > 0) {
	#
	# Warn about any invalid PG
	# @bad_pgs is a list of invalid CPUs in the arguments
	#
	my @bad_pgs = $p->set_subtract(\@all_pgs, \@pg_list);
	if (scalar @bad_pgs) {
		printf STDERR
		  gettext("%s: warning: invalid PG IDs %s\n"),
		    $cmdname, $p->id_collapse(@bad_pgs);
	}
}

# Do we have any PGs left?
if (scalar(@pgs) == 0) {
	printf STDERR
	gettext("%s: No processor groups matching command line arguments\n"),
	    $cmdname;
	exit(E_USAGE);
}

#
# Set $do_levels if we should provide output identation by level It doesn't make
# sense to provide identation if PGs are sorted not in topology order.
#
my $do_levels = ($sort_key eq 'breadth' || $sort_key eq 'depth');

#
# %name_of_pg hash keeps sharing name, possibly with physical tags appended to
# it for each PG.
#
my %name_of_pg;

#
# For calculating proper offsets we need to know minimum and maximum level for
# all PGs
#
my $max_sharename_len = length('RELATIONSHIP');

my $maxlevel;
my $minlevel;

if ($do_levels) {
	my @levels = map { $p->level($_) } @pgs;	# Levels for each PG
	$maxlevel = max(@levels);
	$minlevel = min(@levels);
}

#
# Walk over all PGs and find out the string length that we need to represent
# sharing name + physical tags + indentation level.
#
foreach my $pg (@pgs) {
	my $name =  $p->sh_name ($pg) || "unknown";
	my $level = $p->level($pg) || 0 if $do_levels;

	if ($do_physical) {
		my $tags = $p->tags($pg);
		$name = "$name [$tags]" if $tags;
		$name_of_pg{$pg} = $name;
	}

	$name_of_pg{$pg} = $name;
	my $length = length($name);
	$length += $level - $minlevel if $do_levels;
	$max_sharename_len = $length if $length > $max_sharename_len;
}

# Maximum length of PG ID field
my $max_pg_len = length(max(@pgs)) + 1;
$max_pg_len = length('PG') if ($max_pg_len) < length('PG');

#
#
# %pgs hash contains various statistics per PG that is used for sorting.
my %pgs;

# Total number of main loop iterations we actually do
my $total_iterations = 0;

#
# For summary, keep track of minimum and maximum data per PG
#
my $history;

#
# Provide summary output when aggregation is requested and user hits ^C
#
$SIG{'INT'} = \&print_totals if $do_aggregate;

######################################################################
# Main loop
###########

while ($infinite || $count--) {
	#
	# Print timestamp if -T is specified
	#
	if ($do_timestamp) {
		if ($do_timestamp eq 'u') {
			print time(), "\n";
		} else {
			my $date_str = strftime "%A, %B %e, %Y %r %Z",
			  localtime;
			print "$date_str\n";
		}
	}

	#
	# Wait for the requested interval
	#
	select(undef, undef, undef, $interval);

	#
	# Print headers
	# There are two different output formats - one regular and one verbose
	#
	if (!$verbose) {
		printf "%-${max_pg_len}s  %-${max_sharename_len}s ".
		  "$pcnt_fmt  $pcnt_fmt  %-s\n",
		  'PG', 'RELATIONSHIP', 'HW', 'SW', 'CPUS';
	} else {
		printf "%-${max_pg_len}s  %-${max_sharename_len}s" .
		  " $pcnt_fmt %4s %4s $pcnt_fmt $pcnt_fmt $pcnt_fmt $pcnt_fmt %s\n",
		  'PG','RELATIONSHIP',
		  'HW', 'UTIL', 'CAP',
		  'SW', 'USR', 'SYS', 'IDLE', 'CPUS';
	}

	#
	# Update the data in one of the snapshots
	#
	$p_dup->update();

	#
	# Do not show offlined CPUs
	#
	my @online_cpus = $p->online_cpus();

	#
	# Check whether both snapshots belong to the same generation
	#
	if ($p->generation() != $p_dup->generation()) {
		printf gettext("Configuration changed!\n");
		# Swap $p and $p_dup;
		$p = $p_dup;
		$p_dup = Sun::Solaris::Pg->new(
					       -cpudata => $do_cpu_utilization,
					       -swload => 1,
					       -tags => $do_physical,
					       -retry => RETRY_COUNT,
					       -delay => RETRY_DELAY);
		if (!$p_dup) {
			printf STDERR gettext(
			  "%s: can not obtain Processor Group information: $!\n"),
			    $cmdname;
			exit(E_ERROR);
		}
		#
		# Recreate @pg_list since it may have changed
		#
		@pgs = get_pg_list($p, \@pg_list,
				   \@sharing_filter, \@sharing_filter_neg);

		next;
	}

	%pgs = ();

	#
	# Go over each PG and gets its utilization data
	#
	foreach my $pg (@pgs) {
		my ($hwload, $utilization, $capacity, $accuracy) =
		  get_load($p, $p_dup, $pg);
		my @cpus = $p->cpus ($pg);
		my ($user, $sys, $idle, $swload) =
		  $p->sw_utilization($p_dup, $pg);

		# Adjust idle and swload based on rounding
		($swload, $idle) = get_swload($user, $sys);

		$pgs{$pg}->{pg} = $pg;
		$pgs{$pg}->{hwload} = $hwload;
		$pgs{$pg}->{swload} = $swload;
		$pgs{$pg}->{user} = $user;
		$pgs{$pg}->{sys} = $sys;
		$pgs{$pg}->{idle} = $idle;
		$pgs{$pg}->{utilization} = $utilization;
		$pgs{$pg}->{capacity} = $capacity;

		#
		# Record history
		#
		$history->{$pg}->{hwload} += $hwload if $hwload && $hwload >= 0;
		$history->{$pg}->{swload} += $swload if $swload;
		$history->{$pg}->{user} += $user if $user;
		$history->{$pg}->{sys} += $sys if $sys;
		$history->{$pg}->{idle} += $idle if $idle;
		$history->{$pg}->{maxhwload} = $hwload if
		  !defined($history->{$pg}->{maxhwload}) ||
		    $hwload > $history->{$pg}->{maxhwload};
		$history->{$pg}->{minhwload} = $hwload if
		  !defined($history->{$pg}->{minhwload}) ||
		    $hwload < $history->{$pg}->{minhwload};
		$history->{$pg}->{maxswload} = $swload if
		  !defined($history->{$pg}->{maxswload}) ||
		    $swload > $history->{$pg}->{maxswload};
		$history->{$pg}->{minswload} = $swload if
		  !defined($history->{$pg}->{minswload}) ||
		    $swload < $history->{$pg}->{minswload};
	}

	#
	# Sort the output
	#
	my @sorted_pgs;
	my $npgs = scalar @pgs;
	@sorted_pgs = pg_sort_by_key(\%pgs, $sort_key, $sort_reverse, @pgs);

	#
	# Should only top N be displayed?
	#
	if ($show_top) {
		$npgs = $show_top if $show_top < $npgs;
		@sorted_pgs = @sorted_pgs[0..$npgs - 1];
	}

	#
	# Now print everything
	#
	foreach my $pg (@sorted_pgs) {
		my $shname = $name_of_pg{$pg};
		my $level;

		if ($do_levels) {
			$level = $p->level($pg) - $minlevel;
			$shname = (' ' x (LEVEL_OFFSET * $level)) . $shname;
		}

		my $hwload = $pgs{$pg}->{hwload} || 0;
		my $swload = $pgs{$pg}->{swload};

		my @cpus = $p->cpus($pg);
		@cpus = $p->intersect(\@cpus, \@online_cpus);

		my $cpus = $p->id_collapse(@cpus);
		my $user = $pgs{$pg}->{user};
		my $sys = $pgs{$pg}->{sys};
		my $idle = $pgs{$pg}->{idle};
		my $utilization = $pgs{$pg}->{utilization};
		my $capacity = $pgs{$pg}->{capacity};

		if (!$verbose) {
			printf "%${max_pg_len}d  %-${max_sharename_len}s " .
			  "%s  %s  %s\n",
			    $pg, $shname,
			    load2str($hwload),
			    load2str($swload),
			    $cpus;
		} else {
			printf
			  "%${max_pg_len}d  %-${max_sharename_len}s " .
			    "%4s %4s %4s %4s %4s %4s %4s %s\n",
			    $pg, $shname,
			      load2str($hwload),
			      number_to_scaled_string($utilization),
			      number_to_scaled_string($capacity),
			      load2str($swload),
			      load2str($user),
			      load2str($sys),
			      load2str($idle),
			      $cpus;
		}

		#
		# If per-CPU utilization is requested, print it after each
		# corresponding PG
		#
		if ($do_cpu_utilization) {
			my $w = ${max_sharename_len} - length ('CPU');
			foreach my $cpu (sort {$a <=> $b }  @cpus) {
				my ($cpu_utilization,
				    $accuracy, $hw_utilization,
				   $swload) =
				     $p->cpu_utilization($p_dup, $pg, $cpu);
				next unless defined $cpu_utilization;
				my $cpuname = "CPU$cpu";
				if ($do_levels) {
					$cpuname =
					  (' ' x (LEVEL_OFFSET * $level)) .
					    $cpuname;

				}

				printf "%-${max_pg_len}s  " . 
				  "%-${max_sharename_len}s ",
				  ' ', $cpuname;
				if ($verbose) {
				    printf "%s %4s %4s\n",
				      load2str($cpu_utilization),
				      number_to_scaled_string($hw_utilization),
				      number_to_scaled_string($capacity);
				} else {
					printf "%s  %s\n",
					  load2str($cpu_utilization),
					  load2str($swload);
				}
			}
		}
	}

	#
	# Swap $p and $p_dup
	#
	($p, $p_dup) = ($p_dup, $p);

	$total_iterations++;
}

print_totals() if $do_aggregate;


####################################
# End of main loop
####################################


#
# Support Subroutines
#

#
# Print aggregated information in the end
#
sub print_totals
{
	exit ($rc) unless $total_iterations > 1;

	printf gettext("\n%s SUMMARY: UTILIZATION OVER %d SECONDS\n\n"),
	  ' ' x 10,
	  $total_iterations * $interval;

	my @sorted_pgs;
	my $npgs = scalar @pgs;

	%pgs = ();

	#
	# Collect data per PG
	#
	foreach my $pg (@pgs) {
		$pgs{$pg}->{pg} = $pg;

		my ($hwload, $utilization, $capacity, $accuracy) =
		  get_load($p_initial, $p_dup, $pg);

		my @cpus = $p->cpus ($pg);
		my ($user, $sys, $idle, $swload) =
		  $p_dup->sw_utilization($p_initial, $pg);

		# Adjust idle and swload based on rounding
		($swload, $idle) = get_swload($user, $sys);

		$pgs{$pg}->{pg} = $pg;
		$pgs{$pg}->{swload} = $swload;
		$pgs{$pg}->{user} = $user;
		$pgs{$pg}->{sys} = $sys;
		$pgs{$pg}->{idle} = $idle;
		$pgs{$pg}->{hwload} = $hwload;
		$pgs{$pg}->{utilization} = number_to_scaled_string($utilization);
		$pgs{$pg}->{capacity} = number_to_scaled_string($capacity);
		$pgs{$pg}->{minhwload} = $history->{$pg}->{minhwload};
		$pgs{$pg}->{maxhwload} = $history->{$pg}->{maxhwload};
		$pgs{$pg}->{minswload} = $history->{$pg}->{minswload} || 0;
		$pgs{$pg}->{maxswload} = $history->{$pg}->{maxswload} || 0;
	}

	#
	# Sort PGs according to the sorting options
	#
	@sorted_pgs = pg_sort_by_key(\%pgs, $sort_key, $sort_reverse, @pgs);

	#
	# Trim to top N if needed
	#
	if ($show_top) {
		$npgs = $show_top if $show_top < $npgs;
		@sorted_pgs = @sorted_pgs[0..$npgs - 1];
	}

	#
	# Print headers
	#
	my $d = ' ' . '-' x 4;
	if ($verbose) {
		printf "%${max_pg_len}s  %-${max_sharename_len}s %s " .
		  "  ------HARDWARE------ ------SOFTWARE------\n",
		  ' ', ' ', ' ' x 8;

		printf "%-${max_pg_len}s  %-${max_sharename_len}s",
		  'PG', 'RELATIONSHIP';

		printf " %4s %4s", 'UTIL', ' CAP';
		printf "  $pcnt_fmt $pcnt_fmt $pcnt_fmt $pcnt_fmt $pcnt_fmt $pcnt_fmt %s\n",
		   'MIN', 'AVG', 'MAX', 'MIN', 'AVG', 'MAX', 'CPUS';
	} else {
		printf  "%${max_pg_len}s  %-${max_sharename_len}s " .
		  "------HARDWARE------" .
		  " ------SOFTWARE------\n", ' ', ' ';

		printf "%-${max_pg_len}s  %-${max_sharename_len}s",
		  'PG', 'RELATIONSHIP';

		printf " $pcnt_fmt $pcnt_fmt $pcnt_fmt $pcnt_fmt $pcnt_fmt $pcnt_fmt %s\n",
		   'MIN', 'AVG', 'MAX', 'MIN', 'AVG', 'MAX', 'CPUS';
	}

	#
	# Print information per PG
	#
	foreach my $pg (@sorted_pgs) {
		my $cpus = $p->cpus($pg);

		my $shname = $name_of_pg{$pg};
		if ($sort_key eq 'breadth' || $sort_key eq 'depth') {
			my $level = $p->level($pg) - $minlevel;
			$shname = (' ' x (LEVEL_OFFSET * $level)) . $shname;
		}

		printf "%${max_pg_len}d  %-${max_sharename_len}s ",
		  $pg, $shname;

		if ($verbose) {
			printf "%4s %4s  ",
			  number_to_scaled_string($pgs{$pg}->{utilization}),
			    number_to_scaled_string($pgs{$pg}->{capacity});
		}

		if (!defined($pgs{$pg}->{hwload}) ||
		    $pgs{$pg}->{hwload} == HWLOAD_UNDEF) {
			printf "$pcnt_fmt $pcnt_fmt $pcnt_fmt ",
			  '-', '-', '-';
		} else {
			printf "%s %s %s ",
			  load2str($pgs{$pg}->{minhwload}),
			  load2str($pgs{$pg}->{hwload}),
			  load2str($pgs{$pg}->{maxhwload});
		}
		printf "%s %s %s",
		  load2str($pgs{$pg}->{minswload}),
		  load2str($pgs{$pg}->{swload}),
		  load2str($pgs{$pg}->{maxswload});

		printf " %s\n", $cpus;
	}

	exit ($rc);
}

#
# pg_sort_by_key(pgs, key, inverse)
# Sort pgs according to the key specified
#
# Arguments:
#   pgs hash indexed by PG ID
#   sort keyword
#   inverse - inverse sort result if this is T
#
sub pg_sort_by_key
{
	my $pgs = shift;
	my $key = shift;
	my $inverse = shift;
	my @sorted;

	if ($key eq 'depth' || $key eq 'breadth') {
		my $root = $p->root;
		my @pgs = $key eq 'depth' ?
		  $p->all_depth_first() :
		  $p->all_breadth_first();
		@sorted = reverse(grep { exists($pgs{$_}) } @pgs);
	} else {
		@sorted = sort { $pgs{$a}->{$key} <=> $pgs{$b}->{$key} } @_;
	}

	return ($inverse ? reverse(@sorted) : @sorted);
}

#
# Convert numeric load to formatted string
#
sub load2str
{
	my $load = shift;

	return (sprintf "$pcnt_fmt", '-') if
	  !defined($load) || $load == HWLOAD_UNDEF;
	return (sprintf "$pcnt_fmt", '?') if $load == HWLOAD_UNKNOWN;
	return (sprintf "$pcnt%%", $load);
}

#
# get_load(snapshot1, snapshot2, pg)
#
# Get various hardware load data for the given PG using two snapshots.
# Arguments: two PG snapshots and PG ID
#
# In scalar context returns the hardware load
# In list context returns a list
# (load, utilization, capacity, accuracy)
#
sub get_load
{
	my $p = shift;
	my $p_dup = shift;
	my $pg = shift;

	return HWLOAD_UNDEF if !$p->has_utilization($pg);

	my ($capacity, $utilization, $accuracy, $tdelta);


	$accuracy = 100;
	$utilization = 0;

	$utilization = $p->utilization($p_dup, $pg) || 0;
	$capacity = $p_dup->capacity($pg);
	$accuracy = $p->accuracy($p_dup, $pg) || 0;
	$tdelta = $p->tdelta($p_dup, $pg);
	my $utilization_per_second = $utilization;
	$utilization_per_second /= $tdelta if $tdelta;

	my $load;

	if ($accuracy != 100) {
		$load = HWLOAD_UNKNOWN;
	} else {
		$load = $capacity ?
		  $utilization_per_second * 100 / $capacity :
		  HWLOAD_UNKNOWN;
		$capacity *= $tdelta if $tdelta;
	}

	return (wantarray() ?
		($load, $utilization, $capacity, $accuracy) :
		$load);
}

#
# Make sure that with the rounding used, user + system + swload add up to 100%.
#
#
sub get_swload
{
	my $user = shift;
	my $sys = shift;
	my $swload;
	my $idle;

	$user = sprintf "$pcnt", $user;
	$sys  = sprintf  "$pcnt", $sys;

	$swload = $user + $sys;
	$idle = 100 - $swload;

	return ($swload, $idle);
}

#
# get_pg_list(cookie, pg_list, sharing_filter, sharing_filter_neg) Get list OF
# PGs to look at based on all PGs available, user-specified PGs and
# user-specified filters.
#
sub get_pg_list
{
	my $p = shift;
	my $pg_list = shift;
	my $sharing_filter = shift;
	my $sharing_filter_neg = shift;

	my @all = $p->all();
	my @pg_list = scalar @$pg_list ? @$pg_list : @all;
	my @pgs = $p->intersect(\@all_pgs, \@pg_list);

	#
	# Now we have list of PGs to work with. Now apply filtering. First list
	# only those matching -R
	#
	@pgs = grep { list_match($p->sh_name($_), \@sharing_filter, 0) } @pgs if
	  @sharing_filter;

	my @sharing_filter = @$sharing_filter;
	my @sharing_filter_neg = @$sharing_filter_neg;
	# Remove any that doesn't match -r
	@pgs = grep {
		!list_match($p->sh_name($_), \@sharing_filter_neg, 0)
	} @pgs if
	  scalar @sharing_filter_neg;

	return (@pgs);
}

#
# usage(rc)
#
# Print short usage message and exit with the given return code.
# If verbose is T, print a bit more information
#
sub usage
{
	my $rc = shift || E_SUCCESS;

	printf STDERR
	  gettext("Usage:\t%s [-A] [-C] [-p] [-s key | -S key] " .
		  "[-t number] [-T u | d]\n"), $cmdname;
	print STDERR
	  gettext("\t\t[-r string] [-R string] [-P pg ...] [-c processor_id... ]\n");
	print STDERR
	  gettext("\t\t[interval [count]]\n\n");

	exit ($rc);
}

#
# list_match(val, list_ref, strict)
# Return T if argument matches any of the elements on the list, undef otherwise.
#
sub list_match
{
	my $arg = shift;
	my $list = shift;
	my $strict = shift;

	return first { $arg eq $_ } @$list if $strict;
	return first { $arg =~ m/$_/i } @$list;
}

#
# Convert a number to a string representation
# The number is scaled down until it is small enough to be in a good
# human readable format i.e. in the range 0 thru 1000.
# If it's smaller than 10 there's room enough to provide one decimal place.
#
sub number_to_scaled_string
{
	my $number = shift;

	return '-' unless defined ($number);

	# Remove any trailing spaces
	$number =~ s/ //g;

	return $number unless $number =~ /^[.\d]+$/;

	my $scale = 1000;

	return sprintf("%4d", $number) if $number < $scale;

	my @measurement = ('K', 'M', 'B', 'T');
	my $uom = shift(@measurement);
	my $result;

	my $save = $number;

	# Get size in K.
	$number /= $scale;

	while (($number >= $scale) && $uom ne 'B') {
		$uom = shift(@measurement);
		$save = $number;
		$number /= $scale;
	}

	# check if we should output a decimal place after the point
	if ($save && (($save / $scale) < 10)) {
		$result = sprintf("%3.1f$uom", $save / $scale);
	} else {
		$result = sprintf("%3d$uom", $number);
	}

	return ("$result");
}


__END__
