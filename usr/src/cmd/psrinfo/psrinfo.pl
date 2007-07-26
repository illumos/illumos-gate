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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# psrinfo: displays information about processors
#
# See detailed comment in the end of this file.
#

use strict;
use warnings;
use locale;
use POSIX qw(locale_h strftime);
use File::Basename;
use Getopt::Long qw(:config no_ignore_case bundling auto_version);
use Sun::Solaris::Utils qw(textdomain gettext);
use Sun::Solaris::Kstat;

# Set message locale
setlocale(LC_ALL, "");
textdomain(TEXT_DOMAIN);

######################################################################
# Configuration variables
######################################################################

# Regexp describing cpu_info kstat fields describing CPU hierarchy.
my $valid_id_exp = qr{^(?:chip|core)_id$};

# Translation of kstat name to human-readable form
my %translations = ('chip_id' => gettext("The physical processor"),
		    'core_id' => gettext("The core"));

# Localized version of plural forms
my %pluralized_names = ('processor'	=> gettext("processor"),
			'processors'	=> gettext("processors"),
			'chip'		=> gettext("chip"),
			'chips'		=> gettext("chips"),
			'core'		=> gettext("core"),
			'cores'		=> gettext("cores"));

# Localized CPU states
my %cpu_states = ('on-line'	=> gettext("on-line"),
		  'off-line'	=> gettext("off-line"),
		  'faulted'	=> gettext("faulted"),
		  'powered-off' => gettext("powered-off"),
		  'no-intr'	=> gettext("no-intr"),
		  'spare'	=> gettext("spare"),
		  'unknown'	=> gettext("unknown"));

######################################################################
# Global variables
######################################################################

# Hash with CPU ID as a key and specific per-cpu kstat hash as a value
our %cpu_list;

# Command name without path and trailing .pl - used for error messages.
our $cmdname = basename($0, ".pl");

# Return value
our $errors = 0;

######################################################################
# Helper subroutines
######################################################################

#
# Print help string if specified or the standard help message and exit setting
# errno.
#
sub usage
{
	my (@msg) = @_;
	print STDERR $cmdname, ": @msg\n" if (@msg);
	print STDERR gettext("usage: \n" .
			 "\tpsrinfo [-v] [-p] [processor_id ...]\n" .
			 "\tpsrinfo -s [-p] processor_id\n");
	exit(2);
}

#
# Return the input list with duplicates removed.
# Count how many times we've seen each element and remove elements seen more
# than once.
#
sub uniq
{
	my %seen;	# Have we seen this element already?
	return (grep { ++$seen{$_} == 1 } @_);
}

#
# Return the intersection of two lists passed by reference
# Convert the first list to a hash with seen entries marked as 1-values
# Then grep only elements present in the first list from the second list.
# As a little optimization, use the shorter list to build a hash.
#
sub intersect
{
	my ($left, $right) = @_;
	my %seen;	# Set to 1 for everything in the first list
	# Put the shortest list in $left
	scalar @$left <= scalar @$right or ($right, $left) = ($left, $right);

	# Create a hash indexed by elements in @left with ones as a value.
	map { $seen{$_} = 1 } @$left;
	# Find members of @right present in @left
	return (grep { $seen{$_} } @$right);
}

#
# Return elements of the second list not present in the first list. Both lists
# are passed by reference.
#
sub set_subtract
{
	my ($left, $right) = @_;
	my %seen;	# Set to 1 for everything in the first list
	# Create a hash indexed by elements in @left with ones as a value.
	map { $seen{$_} = 1 } @$left;
	# Find members of @right present in @left
	return (grep { ! $seen{$_} } @$right);
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

#
# Return the maximum value of its arguments
#
sub max
{
	my $m = shift;

	foreach my $el (@_) {
		$m = $el if $m < $el;
	}
	return ($m);
}

#
# Pluralize name if there is more than one instance
# Arguments: name, ninstances
#
sub pluralize
{
	my ($name, $count) = @_;
	# Remove trailing '_id' from the name.
	$name =~ s/_id$//;
	my $plural_name = $count > 1 ? "${name}s" : $name;
	return ($pluralized_names{$plural_name} || $plural_name)
}

#
# Translate id name into printable form
# Look at the %translations table and replace everything found there
# Remove trailing _id from the name if there is no translation
#
sub id_translate
{
	my $name = shift or return;
	my $translated_name = $translations{$name};
	$name =~ s/_id$// unless $translated_name;
	return ($translated_name || $name);
}

#
# Consolidate consequtive CPU ids as start-end
# Input: list of CPUs
# Output: string with space-sepated cpu values with CPU ranges
#   collapsed as x-y
#
sub collapse
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

#
# Expand start-end into the list of values
# Input: string containing a single numeric ID or x-y range
# Output: single value or a list of values
# Ranges with start being more than end are inverted
#
sub expand
{
	my $arg = shift;

	if ($arg =~ m/^\d+$/) {
		# single number
		return ($_);
	} elsif ($arg =~ m/^(\d+)\-(\d+)$/) {
		my ($start, $end) = ($1, $2);	# $start-$end
		# Reverse the interval if start > end
		($start, $end) = ($end, $start) if $start > $end;
		return ($start .. $end);
	} elsif ($arg =~ m/-/) {
		printf STDERR
		  gettext("%s: invalid processor range %s\n"),
		    $cmdname, $_;
	} else {
		printf STDERR
		  gettext("%s: processor %s: Invalid argument\n"),
		    $cmdname, $_;
	}
	$errors = 2;
	return ();
}

#
# Functions for constructing CPU hierarchy. Only used with -vp option.
#

#
# Return numerically sorted list of distinct values of a given cpu_info kstat
# field, spanning given CPU set.
#
# Arguments:
#   Property name
#   list of CPUs
#
# Treat undefined values as zeroes.
sub property_list
{
	my $prop_name = shift;
	return (grep {$_ >= 0} uniqsort(map { $cpu_list{$_}->{$prop_name} || 0 } @_));
}

#
# Return subset of CPUs sharing specified value of a given cpu_info kstat field.
# Arguments:
#   Property name
#   Property value
#   List of CPUs to select from
#
# Treat undefined values as zeroes.
sub cpus_by_prop
{
	my $prop_name = shift;
	my $prop_val = shift;

	return (grep { ($cpu_list{$_}->{$prop_name} || 0) == $prop_val } @_);
}

#
# Build component tree
#
# Arguments:
#    Reference to the list of CPUs sharing the component
#    Reference to the list of sub-components
#
sub build_component_tree
{
	my ($cpus, $comp_list) = @_;
	# Get the first component and the rest
	my ($comp_name, @comps) = @$comp_list;
	my $tree = {};
	if (!$comp_name) {
		$tree->{cpus} = $cpus;
		return ($tree);
	}

	# Get all possible component values
	foreach my $v (property_list($comp_name, @$cpus)) {
		my @comp_cpus = cpus_by_prop ($comp_name, $v, @$cpus);
		$tree->{name} = $comp_name;
		$tree->{cpus} = $cpus;
		$tree->{values}->{$v} = build_component_tree(\@comp_cpus,
							     \@comps);
	}
	return ($tree);
}

#
# Print the component tree
# Arguments:
#   Reference to a tree
#   indentation
# Output: maximum indentation
#
sub print_component_tree
{
	my ($tree, $ind) = @_;
	my $spaces = ' ' x $ind; # indentation string
	my $vals = $tree->{values};
	my $retval = $ind;
	if ($vals) {
		# This is not a leaf node
		# Get node name and translate it to printable format
		my $id_name = id_translate($tree->{name});
		# Examine each sub-node
		foreach my $comp_val (nsort(keys %$vals)) {
			my $child_tree = $vals->{$comp_val}; # Sub-tree
			my $child_id = $child_tree->{name}; # Name of child node
			my @cpus = @{$child_tree->{cpus}}; # CPUs for the child
			my $ncpus = scalar @cpus; # Number of CPUs
			my $cpuname = pluralize('processor', $ncpus);
			my $cl = collapse(@cpus); # Printable CPU list
			if (!$child_id) {
				# Child is a leaf node
				print $spaces;
				printf gettext("%s has %d virtual %s"),
				       $id_name, $ncpus, $cpuname;
				print " ($cl)\n";
				$retval = max($retval, $ind + 2);
			} else {
				# Child has several values. Let's see how many
				my $grandchild_tree = $child_tree->{values};
				my $nvals = scalar(keys %$grandchild_tree);
				my $child_id_name = pluralize($child_id,
							      $nvals);
				print $spaces;
				printf
				  gettext("%s has %d %s and %d virtual %s"),
				    $id_name, $nvals, $child_id_name, $ncpus,
				      $cpuname;
				print " ($cl)\n";
				# Print the tree for the child
				$retval = max($retval,
					      print_component_tree($child_tree,
								   $ind + 2));
			}
		}
	}
	return ($retval);
}


############################
# Main part of the program
############################

#
# Option processing
#
my ($opt_v, $opt_p, $opt_silent);

GetOptions("p" => \$opt_p,
 	   "v" => \$opt_v,
 	   "s" => \$opt_silent) || usage();


my $verbosity = 1;
my $phys_view;

$verbosity |= 2 if $opt_v;
$verbosity &= ~1 if $opt_silent;
$phys_view = 1 if $opt_p;

# Set $phys_verbose if -vp is specified
my $phys_verbose = $phys_view && ($verbosity > 1);

# Verify options
usage(gettext("options -s and -v are mutually exclusive")) if $verbosity == 2;

usage(gettext("must specify exactly one processor if -s used")) if
  (($verbosity == 0) && scalar @ARGV != 1);

#
# Read cpu_info kstats
#
my $ks = Sun::Solaris::Kstat->new(strip_strings => 1) or
  (printf STDERR gettext("%s: kstat_open() failed: %s\n"),
   $cmdname, $!),
    exit(2);
my $cpu_info = $ks->{cpu_info} or
  (printf STDERR gettext("%s: can not read cpu_info kstats\n"),
   $cmdname),
    exit(2);

my (
    @all_cpus,	# List of all CPUs in the system
    @cpu_args,	# CPUs to look at
    @cpus,	# List of CPUs to process
    @id_list,	# list of various xxx_id kstats representing CPU topology
    %chips,	# Hash with chip ID as a key and reference to the list of
		# virtual CPU IDs, belonging to the chip as a value
    @chip_list,	# List of all chip_id values
    $ctree,	# The component tree
   );

#
# Get information about each CPU.
#
#   Collect list of all CPUs in @cpu_list array
#
#   Construct %cpu_list hash keyed by CPU ID with cpu_info kstat hash as its
#   value.
#
#   Construct %chips hash keyed by chip ID. It has a 'cpus' entry, which is
#   a reference to a list of CPU IDs within a chip.
#
foreach my $id (nsort(keys %$cpu_info)) {
	# $id is CPU id
	my $info = $cpu_info->{$id};

	#
	# The name part of the cpu_info kstat should always be a string
	# cpu_info$id.
	#
	# The $ci hash reference holds all data for a specific CPU id.
	#
	my $ci = $info->{"cpu_info$id"} or next;
	# Save CPU-specific information in cpu_list hash, indexed by CPU ID.
	$cpu_list{$id} = $ci;
	my $chip_id = $ci->{'chip_id'};
	# Collect CPUs within the chip.
	# $chips{$chip_id} is a reference to a list of CPU IDs belonging to thie
	# chip. It is automatically created when first referenced.
	push (@{$chips{$chip_id}}, $id) if (defined($chip_id));
	# Collect list of CPU IDs in @cpus
	push (@all_cpus, $id);
}

#
# Figure out what CPUs to examine.
# Look at specific CPUs if any are specified on the command line or at all CPUs
# CPU ranges specified in the command line are expanded into lists of CPUs
#
if (scalar(@ARGV) == 0) {
	@cpu_args = @all_cpus;
} else {
	# Expand all x-y intervals in the argument list
	@cpu_args = map { expand($_) } @ARGV;

	usage(gettext("must specify exactly one processor if -s used")) if
	    (($verbosity == 0) && scalar @cpu_args != 1);

	# Detect invalid CPUs in the arguments
	my @bad_args = set_subtract(\@all_cpus, \@cpu_args);
	my $nbadargs = scalar @bad_args;

	if ($nbadargs != 0) {
		# Warn user about bad CPUs in the command line
		my $argstr = collapse(@bad_args);

		if ($nbadargs > 1) {
			printf STDERR gettext("%s: Invalid processors %s\n"),
			  $cmdname, $argstr;
		} else {
			printf STDERR
			  gettext("%s: processor %s: Invalid argument\n"),
			  $cmdname, $argstr;
		}
		$errors = 2;
	}

	@cpu_args = uniqsort(intersect(\@all_cpus, \@cpu_args));
}

#
# In physical view, CPUs specified in the command line are only used to identify
# chips. The actual CPUs are all CPUs belonging to these chips.
#
if (! $phys_view) {
	@cpus = @cpu_args;
} else {
	# Get list of chips spanning all CPUs specified
	@chip_list = property_list('chip_id', @cpu_args);
	if (!scalar @chip_list && $errors == 0) {
		printf STDERR
		  gettext("%s: Physical processor view not supported\n"),
		    $cmdname;
		exit(1);
	}

	# Get list of all CPUs within these chips
	@cpus = uniqsort(map { @{$chips{$_}} } @chip_list);
}


if ($phys_verbose) {
	#
	# 1) Look at all possible xxx_id properties and remove those that have
	#    NCPU values or one value. Sort the rest.
	#
	# 2) Drop ids which have the same number of entries as number of CPUs or
	#    number of chips.
	#
	# 3) Build the component tree for the system
	#
	foreach my $id (keys %$cpu_info) {
		my $info = $cpu_info->{$id};
		my $name = "cpu_info$id";
		my $ci = $info->{$name}; # cpu_info kstat for this CPU

		# Collect all statistic names matching $valid_id_exp
		push @id_list, grep(/$valid_id_exp/, keys(%$ci));
	}

	# Remove duplicates
	@id_list = uniq(@id_list);

	my $ncpus = scalar @cpus;
	my %prop_nvals;		# Number of instances of each property
	my $nchips = scalar @chip_list;

	#
	# Get list of properties which have more than ncpus and less than nchips
	# instances.
	# Also collect number of instances for each property.
	#
	@id_list = grep {
		my @ids = property_list($_, @cpus);
		my $nids = scalar @ids;
		$prop_nvals{$_} = $nids;
		($_ eq "chip_id") ||
		  (($nids > $nchips) && ($nids > 1) && ($nids < $ncpus));
	} @id_list;

	# Sort @id_list by number of instances for each property
	@id_list = sort { $prop_nvals{$a} <=> $prop_nvals{$b} } @id_list;

	$ctree = build_component_tree(\@cpus, \@id_list);
}


#
# Walk all CPUs specified and print information about them.
# Do nothing for physical view - will do everything later.
#
foreach my $id (@cpus) {
	last if $phys_view;	# physical view is handled later
	my $cpu = $cpu_list{$id} or next;

	# Get CPU state and its modification time
	my $mtime = $cpu->{'state_begin'};
	my $mstring = strftime(gettext("%m/%d/%Y %T"), localtime($mtime));
	my $status = $cpu->{'state'} || gettext("unknown");
	# Get localized version of CPU status
	$status = $cpu_states{$status} || $status;

	if ($verbosity == 0) {
		# Print 1 if CPU is online, 0 if offline.
		printf "%d\n", $status eq 'on-line';
	} elsif (! ($verbosity & 2)) {
		printf gettext("%d\t%-8s  since %s\n"),
			$id, $status, $mstring;
	} else {
		printf gettext("Status of virtual processor %d as of: "), $id;
		print strftime(gettext("%m/%d/%Y %T"), localtime());
		print "\n";
		printf gettext("  %s since %s.\n"), $status, $mstring;
		my $clock_speed =  $cpu->{'clock_MHz'};
		my $cpu_type = $cpu->{'cpu_type'};

		# Display clock speed
		if ($clock_speed ) {
			printf
			  gettext("  The %s processor operates at %s MHz,\n"),
			       $cpu_type, $clock_speed;
		} else {
			printf
	      gettext("  the %s processor operates at an unknown frequency,\n"),
			$cpu_type;
		}

		# Display FPU type
		my $fpu = $cpu->{'fpu_type'};
		if (! $fpu) {
			print
			  gettext("\tand has no floating point processor.\n");
		} elsif ($fpu =~ m/^[aeiouy]/) {
			printf
			 gettext("\tand has an %s floating point processor.\n"),
			   $fpu;
		} else {
			printf
			  gettext("\tand has a %s floating point processor.\n"),
			    $fpu;
		}
	}
}

#
# Physical view print
#
if ($phys_view) {
	if ($verbosity == 1) {
		print scalar @chip_list, "\n";
	} elsif ($verbosity == 0) {
		# Print 1 if all CPUs are online, 0 otherwise.
		foreach my $chip_id (@chip_list) {
			# Get CPUs on a chip
			my @chip_cpus = uniqsort(@{$chips{$chip_id}});
			# List of all on-line CPUs on a chip
			my @online_cpus = grep { 
				($cpu_list{$_}->{state}) eq 'on-line'
			} @chip_cpus;

			#
			# Print 1 if number of online CPUs equals number of all
			# CPUs
			#
			printf
			  "%d\n", scalar @online_cpus == scalar @chip_cpus;
		}
	} else {
		# Walk the property tree and print everything in it.
		my $tcores = $ctree->{values};
		my $cname = id_translate($ctree->{name});
		foreach my $chip (nsort(keys %$tcores)) {
			my $chipref = $tcores->{$chip};
			my @chip_cpus = @{$chipref->{cpus}};
			my $ncpus = scalar @chip_cpus;
			my $cpu_id = $chip_cpus[0];
			my $cpu = $cpu_list{$cpu_id};
			my $brand = $cpu->{brand} ||  gettext("(unknown)");
			my $impl = $cpu->{implementation} ||
			  gettext("(unknown)");
			#
			# Remove cpuid and chipid information from
			# implementation string and print it.
			#
			$impl =~ s/(cpuid|chipid)\s*\w+\s+//;
			$brand = '' if $impl && $impl =~ /^$brand/;
			# List of CPUs on a chip
			my $cpu_name = pluralize('processor', $ncpus);
			# Collapse range of CPUs into a-b string
			my $cl = collapse(@chip_cpus);
			my $childname = $chipref->{name};
			if (! $childname) {
				printf gettext("%s has %d virtual %s "),
				       $cname, $ncpus, $cpu_name;
				print "($cl)\n";
				print "  $impl\n" if $impl;
				print "\t$brand\n" if $brand;
			} else {
				# Get child count
				my $nchildren =
				  scalar(keys(%{$chipref->{values}}));
				$childname = pluralize($childname, $nchildren);
				printf
				  gettext("%s has %d %s and %d virtual %s "),
				       $cname, $nchildren, $childname, $ncpus,
				       $cpu_name;
				print "($cl)\n";
				my $ident = print_component_tree ($chipref, 2);
				my $spaces = ' ' x $ident;
				print "$spaces$impl\n" if $impl;
				print "$spaces  $brand\n" if $brand;
			}
		}
	}
}

exit($errors);

__END__

# The psrinfo command displays information about virtual and physical processors
# in a system. It gets all the information from the 'cpu_info' kstat.
#
# See detailed comment in the end of this file.
#
#
#
# This kstat
# has the following components:
#
# module:	cpu_info
# instance:	CPU ID
# name:		cpu_infoID where ID is CPU ID
# class:	misc
#
# The psrinfo command translates this information from kstat-specific
# representation to user-friendly format.
#
# The psrinfo command has several basic modes of operations:
#
# 1) Without options, it displays a line per CPU with CPU ID and its status and
#    the time the status was last set in the following format:
#
#	0       on-line  since MM/DD/YYYY HH:MM:SS
#	1	on-line  since MM/DD/YYYY HH:MM:SS
#	...
#
#    In this mode, the psrinfo command walks the list of CPUs (either from a
#    command line or all CPUs) and prints the 'state' and 'state_begin' fields
#    of cpu_info kstat structure for each CPU. The 'state_begin' is converted to
#    local time.
#
# 2) With -s option and a single CPU ID as an argument, it displays 1 if the CPU
#    is online and 0 otherwise.
#
# 3) With -p option, it displays the number of physical processors in a system.
#    If any CPUs are specified in the command line, it displays the number of
#    physical processors containing all virtual CPUs specified. The physical
#    processor is identified by the 'chip_id' field of the cpu_info kstat.
#
#    The code just walks over all CPUs specified and checks how many different
#    core_id values they span.
#
# 4) With -v option, it displays several lines of information per virtual CPU,
#    including its status, type, operating speed and FPU type. For example:
#
#	Status of virtual processor 0 as of: MM/DD/YYYY HH:MM:SS
#	  on-line since MM/DD/YYYY HH:MM:SS.
#	  The i386 processor operates at XXXX MHz,
#	        and has an i387 compatible floating point processor.
#	Status of virtual processor 1 as of: MM/DD/YYYY HH:MM:SS
#	  on-line since MM/DD/YYYY HH:MM:SS.
#	  The i386 processor operates at XXXX MHz,
#	        and has an i387 compatible floating point processor.
#
# This works in the same way as 1), just more kstat fields are massaged in the
# output.
#
# 5) With -vp option, it reports additional information about each physical
#    processor. This information includes information about sub-components of
#    each physical processor and virtual CPUs in each sub-component. For
#    example:
#
#	The physical processor has 2 cores and 4 virtual processors (0-3)
#	  The core has 2 virtual processors (0 1)
#	  The core has 2 virtual processors (2 3)
#	    x86 (GenuineIntel family 15 model 4 step 4 clock 3211 MHz)
#	      Intel(r) Pentium(r) D CPU 3.20GHz
#
#    The implementation does not know anything about physical CPU components
#    such as cores. Instead it looks at various cpu_info kstat statistics that
#    look like xxx_id and tries to reconstruct the CPU hierarchy based on these
#    fields. This works as follows:
#
#    a) All kstats statistic names matching the $valid_id_exp regular expression
#       are examined and each kstat statistic name is associated with the number
#       of distinct entries in it.
#
#    b) The resulting list of kstat statistic names is sorted according to the
#       number of distinct entries, matching each name. For example, there are
#       fewer chip_id values than core_id values. This implies that the core is
#	a sub-component of a chip.
#
#    c) All kstat names that have the same number of values as the number of
#       physical processors ('chip_id' values) or the number of virtual
#       processors are removed from the list.
#
#    d) The resulting list represents the CPU hierarchy of the machine. It is
#       translated into a tree showing the hardware hierarchy. Each level of the
#       hierarchy contains the name, reference to a list of CPUs at this level
#       and subcomponents, indexed by the value of each component.
#       The example system above is represented by the following tree:
#
#	$tree =
#	{
#	 'name' => 'chip_id',
#	 'cpus' => [ '0', '1', '2', '3' ]
#	 'values' =>
#	 {
#	  '0' =>
#	  {
#	   'name' => 'core_id',
#	   'cpus' => [ '0', '1', '2', '3' ]
#	   'values' =>
#	   {
#	    '0' => { 'cpus' => [ '0', '1' ] }
#	    '1' => { 'cpus' => [ '2', '3' ] },
#	   },
#	  }
#	 },
#	};
#
#       Each node contains reference to a list of virtual CPUs at this level of
#       hierarchy - one list for a system as a whole, one for chip 0 and one two
#       for each cores. node. Non-leaf nodes also contain the symbolic name of
#       the component as represented in the cpu_info kstat and a hash of
#       subnodes, indexed by the value of the component. The tree is built by
#       the build_component_tree() function.
#
#    e) The resulting tree is pretty-printed showing the number of
#       sub-components and virtual CPUs in each sub-component. The tree is
#       printed by the print_component_tree() function.
#
