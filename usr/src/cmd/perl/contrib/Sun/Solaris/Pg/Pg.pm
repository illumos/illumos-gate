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
# Pg.pm provides object-oriented interface to the Solaris
# Processor Group kstats
#
# See comments in the end
#

package Sun::Solaris::Pg;

use strict;
use warnings;
use Sun::Solaris::Kstat;
use Carp;
use Errno;
use List::Util qw(max sum);

our $VERSION = '1.1';

#
# Currently the OS does not have the root PG and PGs constitute a forest of
# small trees. This module gathers all such trees under one root with ID zero.
# If the root is present already, we do not use faked root.
#

my $ROOT_ID = 0;

#
# PG_NO_PARENT means that kstats have PG parent ID and it is set to -1
# PG_PARENT_UNDEF means that kstats have no PG parent ID
#
use constant {
	PG_NO_PARENT	=> -1,
	PG_PARENT_UNDEF => -2,
};

#
# Sorting order between different sharing relationships. This order is used to
# break ties between PGs with the same number of CPUs. If there are two PGs with
# the same set of CPUs, the one with the higher weight will be the parent of the
# one with the lower weight.
#
my %relationships_order = (
			   'CPU_PM_Idle_Power_Domain' => 1,
			   'Integer_Pipeline' => 2,
			   'Cache' => 3,
			   'CPU_PM_Active_Power_Domain' => 4,
			   'Floating_Point_Unit' => 5,
			   'Data_Pipe_to_memory' => 6,
			   'Memory' => 7,
			   'Socket' => 8,
			   'System' => 9,
			  );

#
# Object interface to the library. These are methods that can be used by the
# module user.
#

#
# Create a new object representing PG
# All the heavy lifting is performed by _init function.
# This function performs all the Perl blessing magic.
#
# The new() method accepts arguments in the form of a hash. The following
# subarguments are supported:
#
#   -cpudata	# Collect per-CPU data from kstats if this is T
#   -tags	# Match PGs to physical relationships if this is T
#   -swload	# Collect software CPU load if this is T
#   -retry	# how many times to retry PG initialization when it fails
#   -delay # Delay in seconds between retries
#
# The arguments are passed to _init().
#
sub new
{
	my $class = shift;
	my %args = @_;
	my $retry_count = $args{-retry} || 0;
	my $retry_delay = $args{-delay} || 1;

	my $self =  _init(@_);

	#
	# If PG initialization fails with EAGAIN error and the caller requested
	# retries, retry initialization.
	#
	for (; !$self && ($! == &Errno::EAGAIN) && $retry_count;
	     $retry_count--) {
		select(undef,undef,undef, $retry_delay);
		$self = _init(@_);
	}

	if ($self) {
		bless($self, $class) if defined($class);
		bless($self) unless defined($class);
	}

	return ($self);
}

#
# Functions below use internal function _pg_get which returns PG hash reference
# corresponding to PG ID specified or 'undef' if the PG can't be found.
#

#
# All methods return 'undef' in scalar context and an empty list in list
# context when unrecoverable errors are detected.
#

#
# Return the root ID of PG hierarchy
#
sub root
{
	scalar @_ == 1 or _usage("root(cookie)");
	my $self = shift;

	return unless $self->{PGTREE};

	return ($ROOT_ID);
}

#
# Return list of all pgs numerically sorted In scalar context return number of
# PGs
#
sub all
{
	scalar @_ == 1 or _usage("all(cookie)");
	my $self = shift;
	my $pgtree =  $self->{PGTREE} or return;
	my @ids = keys(%{$pgtree});

	return (wantarray() ? _nsort(@ids) : scalar @ids);
}

#
# Return list of all pgs by walking the tree depth first.
#
sub all_depth_first
{
	scalar @_ == 1 or _usage("all_depth_first(cookie)");
	my $self = shift;

	_walk_depth_first($self, $self->root());
}

#
# Return list of all pgs by walking the tree breadth first.
#
sub all_breadth_first
{
	scalar @_ == 1 or _usage("all_breadth_first(cookie)");
	my $self = shift;

	_walk_breadth_first($self, $self->root());
}

#
# Return list of CPUs in the PG specified
# CPUs returned are numerically sorted
# In scalar context return number of CPUs
#
sub cpus
{
	scalar @_ == 2 or _usage("cpus(cookie, pg)");
	my $pg = _pg_get(shift, shift) or return;
	my @cpus =  @{$pg->{cpus}};

	return (wantarray() ? _nsort(@cpus) : _collapse(@cpus));
}

#
# Return a parent for a given PG
# Returns undef if there is no parent
#
sub parent
{
	scalar @_ == 2 or _usage("parent(cookie, pg)");
	my $pg = _pg_get(shift, shift) or return;
	my $parent = $pg->{parent};

	return (defined($parent) && $parent >= 0 ? $parent : undef);
}

#
# Return list of children for a given PG
# In scalar context return list of children
#
sub children
{
	scalar @_ == 2 or _usage("children(cookie, pg)");
	my $pg = _pg_get(shift, shift) or return;

	my $children = $pg->{children} or return;
	my @children = @{$children};

	return (wantarray() ? _nsort(@children) : scalar @children);
}

#
# Return sharing name for the PG
#
sub sh_name
{
	scalar @_ == 2 or _usage("sh_name(cookie, pg)");
	my $pg = _pg_get(shift, shift) or return;
	return ($pg->{sh_name});
}

#
# Return T if specified PG ID is a leaf PG
#
sub is_leaf
{
	scalar @_ == 2 or _usage("is_leaf(cookie, pg)");
	my $pg = _pg_get(shift, shift) or return;
	return ($pg->{is_leaf});
}

#
# Return leaf PGs
#
sub leaves
{
	scalar @_ == 1 or _usage("leaves(cookie, pg)");

	my $self = shift;

	return (grep { is_leaf($self, $_) } $self->all());
}

#
# Update varying data in the snapshot
#
sub update
{
	scalar @_ == 1 or _usage("update(cookie)");

	my $self = shift;
	my $ks = $self->{KSTAT};

	$ks->update();

	my $pgtree = $self->{PGTREE};
	my $pg_info = $ks->{$self->{PG_MODULE}};

	#
	# Walk PG kstats and copy updated data from kstats to the snapshot
	#
	foreach my $id (keys %$pg_info) {
		my $pg = $pgtree->{$id} or next;

		my $pg_ks = _kstat_get_pg($pg_info, $id,
					  $self->{USE_OLD_KSTATS});
		return unless $pg_ks;

		#
		# Update PG from kstats
		#
		$pg->{util} = $pg_ks->{hw_util};
		$pg->{current_rate} = $pg_ks->{hw_util_rate};
		$pg->{util_rate_max} = $pg_ks->{hw_util_rate_max};
		$pg->{util_time_running} = $pg_ks->{hw_util_time_running};
		$pg->{util_time_stopped} = $pg_ks->{hw_util_time_stopped};
		$pg->{snaptime} = $pg_ks->{snaptime};
		$pg->{generation} = $pg_ks->{generation};
	}

	#
	# Update software load for each CPU
	#
	$self->{CPU_LOAD} = _get_sw_cpu_load($ks);

	#
	# Get hardware load per CPU
	#
	if ($self->{GET_CPU_DATA}) {
		_get_hw_cpu_load($self);
	}

	return (1);
}

#
# Return list of physical tags for the given PG
#
sub tags
{
	scalar @_ == 2 or _usage("tags(cookie, pg)");
	my $pg = _pg_get(shift, shift) or return;

	my $tags = $pg->{tags} or return;

	my @tags = _uniq(@{$tags});

	return (wantarray() ? @tags : join (',', @tags));
}

#
# Return list of sharing relationships in the snapshot Relationships are sorted
# by the level in the hierarchy If any PGs are given on the command line, only
# return sharing relationships for given PGs, but still keep them sorted.
#
sub sharing_relationships
{
	scalar @_ or _usage("sharing_relationships(cookie, [pg, ...])");

	my $self = shift;
	my @pgs = $self->all_breadth_first();

	if (scalar @_ > 0) {
		#
		# Caller specified PGs, remove any PGs not in caller's list
		#
		my %seen;
		map { $seen{$_} = 1 } @_;

		# Remove any PGs not provided by user
		@pgs = grep { $seen{$_} } @pgs;
	}

	return (_uniq(map { $self->sh_name($_) } @pgs));
}

#
# Return PG generation number. If PG is specified in the argument, return its
# generation, otherwise return snapshot generation.
# Snapshot generation is calculated as the total of PG generations
#
sub generation
{
	(scalar @_ == 1 || scalar @_ == 2) or _usage("generation(cookie, [pg])");
	my $self = shift;

	if (scalar @_ == 0) {
		my @generations = map { $_->{generation} }
				  values %{$self->{PGTREE}};
		return (sum(@generations));

	} else {
		my $id = shift;
		my $pg = _pg_get($self, $id) or return;
		return ($pg->{generation});
	}
}

#
# Return level of PG in the tree, starting from root.
# PG level is cached in the $pg->{level} field.
#
sub level
{
	scalar @_ == 2 or _usage("level(cookie, pg)");
	my $self = shift;
	my $pgid = shift;
	my $pg = _pg_get($self, $pgid) or return;

	return $pg->{level} if defined($pg->{level});

	$pg->{level} = 0;

	my $parent = _pg_get($self, $pg->{parent});
	while ($parent) {
		$pg->{level}++;
		$parent = _pg_get($self, $parent->{parent});
	}

	return ($pg->{level});
}

#
# Return T if PG supports utilization We assume that utilization is supported by
# PG if it shows any non-zero time in util_time_running. It is possible that the
# same condition may be caused by cpustat(1) running ever since PG was created,
# but there is not much we can do about it.
#
sub has_utilization
{
	scalar @_ == 2 or _usage("has_utilization(cookie, pg)");
	my $pg = _pg_get(shift, shift) or return;

	return ($pg->{util_time_running} != 0);
}


#
# Return utilization for the PG
# Utilization is a difference in utilization value between two snapshots.
# We can only compare utilization between PGs having the same generation ID.
#
sub utilization
{
	scalar @_ == 3 or _usage("utilization(cookie, cookie1, pg");
	my $c1 = shift;
	my $c2 = shift;
	my $id = shift;

	#
	# Since we have two cookies, update capacity in both
	#
	_capacity_update($c1, $c2, $id);

	my $pg1 = _pg_get($c1, $id) or return;
	my $pg2 = _pg_get($c2, $id) or return;

	#
	# Nothing to return if one of the utilizations wasn't measured
	#
	return unless ($pg1->{util_time_running} && $pg2->{util_time_running});

	#
	# Verify generation IDs
	#
	return unless $pg1->{generation} eq $pg2->{generation};
	my $u1 = $pg1->{util};
	my $u2 = $pg2->{util};
	return unless defined ($u1) && defined ($u2);

	return (abs($u2 - $u1));
}

#
# Return an estimate of PG capacity Capacity is calculated as the maximum of
# observed utilization expressed in units per second or maximum CPU frequency
# for all CPUs.
#
# We store capacity per sharing relationship, assuming that the same sharing has
# the same capacity. This may not be true for heterogeneous systems.
#
sub capacity
{
	scalar @_ == 2 or _usage("capacity(cookie, pg");
	my $self = shift;
	my $pgid = shift;
	my $pg = _pg_get($self, $pgid) or return;
	my $shname = $pg->{sh_name} or return;

	return (max($self->{MAX_FREQUENCY}, $self->{CAPACITY}->{$shname}));
}

#
# Return accuracy of utilization calculation between two snapshots The accuracy
# is determined based on the total time spent running and not running the
# counters. If T1 is the time counters were running during the period and T2 is
# the time they were turned off, the accuracy is T1 / (T1 + T2), expressed in
# percentages.
#
sub accuracy
{
	scalar @_ == 3 or _usage("accuracy(cookie, cookie1, pg)");
	my $c1 = shift;
	my $c2 = shift;
	my $id = shift;
	my $trun;
	my $tstop;

	my $pg1 = _pg_get($c1, $id) or return;
	my $pg2 = _pg_get($c2, $id) or return;

	# Both PGs should have the same generation
	return unless $pg1->{generation} eq $pg2->{generation};

	#
	# Get time spent with running and stopped counters
	#
	$trun = abs($pg2->{util_time_running} -
		    $pg1->{util_time_running});
	$tstop = abs($pg2->{util_time_stopped} -
		     $pg1->{util_time_stopped});

	my $total = $trun + $tstop;

	#
	# Calculate accuracy as percentage
	#
	my $accuracy = $total ? ($trun * 100) / $total : 0;
	$accuracy = int($accuracy + 0.5);
	$accuracy = 100 if $accuracy > 100;
	return ($accuracy);
}

#
# Return time difference in seconds between two snapshots
#
sub tdelta
{
	scalar @_ == 3 or _usage("tdelta(cookie, cookie1, pg)");
	my $c1 = shift;
	my $c2 = shift;
	my $id = shift;

	my $pg1 = _pg_get($c1, $id) or return;
	my $pg2 = _pg_get($c2, $id) or return;

	return unless $pg1->{generation} eq $pg2->{generation};

	my $t1 = $pg1->{snaptime};
	my $t2 = $pg2->{snaptime};
	my $delta = abs($t1 - $t2);
	return ($delta);
}

#
# Return software utilization between two snapshots
# In scalar context return software load as percentage.
# In list context return a list (USER, SYSTEM, IDLE, SWLOAD)
# All loads are returned as percentages
#
sub sw_utilization
{
	scalar @_ == 3 or _usage("tdelta(cookie, cookie1, pg)");

	my $c1 = shift;
	my $c2 = shift;
	my $id = shift;

	my $pg1 = _pg_get($c1, $id) or return;
	my $pg2 = _pg_get($c2, $id) or return;

	return unless $pg1->{generation} eq $pg2->{generation};

	my @cpus = $c1->cpus($id);

	my $load1 = $c1->{CPU_LOAD};
	my $load2 = $c2->{CPU_LOAD};

	my $idle = 0;
	my $user = 0;
	my $sys = 0;
	my $total = 0;
	my $swload = 0;

	foreach my $cpu (@cpus) {
		my $ld1 = $load1->{$cpu};
		my $ld2 = $load2->{$cpu};
		next unless $ld1 && $ld2;

		$idle += $ld2->{cpu_idle} - $ld1->{cpu_idle};
		$user += $ld2->{cpu_user} - $ld1->{cpu_user};
		$sys  += $ld2->{cpu_sys}  - $ld1->{cpu_sys};
	}

	$total = $idle + $user + $sys;

	# Prevent division by zero
	$total = 1 unless $total;

	$swload = ($user + $sys) * 100 / $total;
	$idle   = $idle * 100 / $total;
	$user   = $user * 100 / $total;
	$sys    = $sys  * 100 / $total;

	return (wantarray() ? ($user, $sys, $idle, $swload) : $swload);
}

#
# Return utilization for the PG for a given CPU
# Utilization is a difference in utilization value between two snapshots.
# We can only compare utilization between PGs having the same generation ID.
#
sub cpu_utilization
{
	scalar @_ == 4 or _usage("utilization(cookie, cookie1, pg, cpu");
	my $c1 = shift;
	my $c2 = shift;
	my $id = shift;
	my $cpu = shift;

	my $idle = 0;
	my $user = 0;
	my $sys = 0;
	my $swtotal = 0;
	my $swload = 0;

	#
	# Since we have two cookies, update capacity in both
	#
	_capacity_update($c1, $c2, $id);

	my $pg1 = _pg_get($c1, $id) or return;
	my $pg2 = _pg_get($c2, $id) or return;

	#
	# Nothing to return if one of the utilizations wasn't measured
	#
	return unless ($pg1->{util_time_running} && $pg2->{util_time_running});

	#
	# Nothing to return if CPU data is missing
	#
	return unless $pg1->{cpudata} && $pg2->{cpudata};

	#
	# Verify generation IDs
	#
	return unless $pg1->{generation} eq $pg2->{generation};

	#
	# Get data for the given CPU
	#
	my $cpudata1 = $pg1->{cpudata}->{$cpu};
	my $cpudata2 = $pg2->{cpudata}->{$cpu};

	return unless $cpudata1 && $cpudata2;

	return unless $cpudata1->{generation} == $cpudata2->{generation};

	my $u1 = $cpudata1->{util};
	my $u2 = $cpudata2->{util};
	return unless defined ($u1) && defined ($u2);
	my $hw_utilization = abs ($u1 - $u2);

	#
	# Get time spent with running and stopped counters
	#
	my $trun = abs($cpudata1->{util_time_running} -
		       $cpudata2->{util_time_running});
	my $tstop = abs($cpudata1->{util_time_stopped} -
			$cpudata2->{util_time_stopped});

	my $total = $trun + $tstop;

	#
	# Calculate accuracy as percentage
	#
	my $accuracy = $total ? ($trun * 100) / $total : 0;
	$accuracy = int($accuracy + 0.5);
	$accuracy = 100 if $accuracy > 100;

	my $t1 = $cpudata1->{snaptime};
	my $t2 = $cpudata2->{snaptime};
	my $tdelta = abs ($t1 - $t2);

	my $shname = $pg2->{sh_name} or return;
	my $capacity = max($c2->{MAX_FREQUENCY}, $c2->{CAPACITY}->{$shname});
	my $utilization = $hw_utilization / $tdelta;
	$capacity = $utilization unless $capacity;
	$utilization /= $capacity;
	$utilization *= 100;

	my $ld1 = $c1->{CPU_LOAD}->{$cpu};
	my $ld2 = $c2->{CPU_LOAD}->{$cpu};

	if ($ld1 && $ld2) {
		$idle = $ld2->{cpu_idle} - $ld1->{cpu_idle};
		$user = $ld2->{cpu_user} - $ld1->{cpu_user};
		$sys  = $ld2->{cpu_sys}  - $ld1->{cpu_sys};

		$swtotal = $idle + $user + $sys;

		# Prevent division by zero
		$swtotal = 1 unless $swtotal;

		$swload = ($user + $sys) * 100 / $swtotal;
		$idle   = $idle * 100 / $swtotal;
		$user   = $user * 100 / $swtotal;
		$sys    = $sys  * 100 / $swtotal;
	}

	return (wantarray() ?
		($utilization, $accuracy, $hw_utilization,
		 $swload, $user, $sys, $idle) :
		$utilization);
}

#
# online_cpus(kstat)
# Return list of on-line CPUs
#
sub online_cpus
{
	scalar @_ == 1 or _usage("online_cpus(cookie)");

	my $self = shift or return;
	my $ks = $self->{KSTAT} or return;

	my $cpu_info = $ks->{cpu_info} or return;

	my @cpus = grep {
		my $cp = $cpu_info->{$_}->{"cpu_info$_"};
		my $state = $cp->{state};
		$state eq 'on-line' || $state eq 'no-intr';
	} keys %{$cpu_info};

	return (wantarray() ? @cpus : _nsort(@cpus));
}

#
# Support methods
#
# The following methods are not PG specific but are generally useful for PG
# interface consumers
#

#
# Sort the list numerically
#
sub nsort
{
	scalar @_ > 0 or _usage("nsort(cookie, val, ...)");
	shift;

	return (_nsort(@_));
}

#
# Return the input list with duplicates removed.
# Should be used in list context
#
sub uniq
{
	scalar @_ > 0 or _usage("uniq(cookie, val, ...)");
	shift;

	return (_uniq(@_));
}

#
# Sort list numerically and remove duplicates
# Should be called in list context
#
sub uniqsort
{
	scalar @_ > 0 or _usage("uniqsort(cookie, val, ...)");
	shift;

	return (_uniqsort(@_));
}


#
# Expand all arguments and present them as a numerically sorted list
# x,y is expanded as (x y)
# 1-3 ranges are expandes as (1 2 3)
#
sub expand
{
	scalar @_ > 0 or _usage("expand(cookie, val, ...)");
	shift;

	return (_uniqsort(map { _expand($_) } @_));
}

#
# Consolidate consecutive ids as start-end
# Input: list of ids
# Output: string with space-sepated cpu values with ranges
#   collapsed as x-y
#
sub id_collapse
{
	scalar @_ > 0 or _usage("collapse(cookie, val, ...)");
	shift;

	return _collapse(@_);
}

#
# Return elements of the second list not present in the first list. Both lists
# are passed by reference.
#
sub set_subtract
{
	scalar @_ == 3 or _usage("set_subtract(cookie, left, right)");
	shift;

	return (_set_subtract(@_));
}

#
# Return the intersection of two lists passed by reference
# Convert the first list to a hash with seen entries marked as 1-values
# Then grep only elements present in the first list from the second list.
# As a little optimization, use the shorter list to build a hash.
#
sub intersect
{
	scalar @_ == 3 or _usage("intersect(cookie, left, right)");
	shift;

	return (_set_intersect(@_));
}

#
# Return elements of the second list not present in the first list. Both lists
# are passed by reference.
#
sub _set_subtract
{
	my ($left, $right) = @_;
	my %seen;	# Set to 1 for everything in the first list
	# Create a hash indexed by elements in @left with ones as a value.
	map { $seen{$_} = 1 } @$left;
	# Find members of @right present in @left
	return (grep { ! $seen{$_} } @$right);
}

#
# END OF PUBLIC INTERFACE
#

#
# INTERNAL FUNCTIONS
#

#
# _usage(): print error message and terminate the program.
#
sub _usage
{
	my $msg = shift;
	Carp::croak "Usage: Sun::Solaris::Pg::$msg";
}

#
# Sort the list numerically
# Should be called in list context
#
sub _nsort
{
	return (sort { $a <=> $b } @_);
}

#
# Return the input list with duplicates removed.
# Should be used in list context
#
sub _uniq
{
	my %seen;
	return (grep { ++$seen{$_} == 1 } @_);
}

#
# Sort list numerically and remove duplicates
# Should be called in list context
#
sub _uniqsort
{
	return (sort { $a <=> $b } _uniq(@_));
}

# Get PG from the snapshot by id
sub _pg_get
{
	my $self = shift;
	my $pgid = shift;

	return unless defined $pgid;
	my $pgtree = $self->{PGTREE} or return;

	return ($pgtree->{$pgid});
}

#
# Copy data from kstat representation to our representation
# Arguments:
#   PG kstat
#   Reference to the list of CPUs.
# Any CPUs in the PG kstat not present in the CPU list are ignored.
#
sub _pg_create_from_kstat
{
	my $pg_ks = shift;
	my $all_cpus = shift;
	my %all_cpus;
	my $pg = ();

	#
	# Mark CPUs available
	#
	map { $all_cpus{$_}++ } @$all_cpus;

	return unless $pg_ks;

	#
	# Convert CPU list in the kstat from x-y,z form to the proper list
	#
	my @cpus = _expand($pg_ks->{cpus});

	#
	# Remove any CPUs not present in the arguments
	#
	@cpus = grep { $all_cpus{$_} } @cpus;

	#
	# Do not create PG unless it has any CPUs
	#
	return unless scalar @cpus;

	#
	# Copy data to the $pg structure
	#
	$pg->{ncpus} = scalar @cpus;
	$pg->{cpus} = \@cpus;
	$pg->{id} = defined($pg_ks->{pg_id}) ? $pg_ks->{pg_id} : $pg_ks->{id};
	$pg->{util} = $pg_ks->{hw_util};
	$pg->{current_rate} = $pg_ks->{hw_util_rate};
	$pg->{util_rate_max} = $pg_ks->{hw_util_rate_max};
	$pg->{util_time_running} = $pg_ks->{hw_util_time_running};
	$pg->{util_time_stopped} = $pg_ks->{hw_util_time_stopped};
	$pg->{snaptime} = $pg_ks->{snaptime};
	$pg->{generation} = $pg_ks->{generation};
	$pg->{sh_name} = $pg_ks->{relationship} || $pg_ks->{sharing_relation};
	$pg->{parent} = $pg_ks->{parent_pg_id};
	$pg->{parent} = PG_PARENT_UNDEF unless defined $pg->{parent};
	#
	# Replace spaces with underscores in sharing names
	#
	$pg->{sh_name} =~ s/ /_/g;
	$pg->{is_leaf} = 1;

	return $pg;
}

#
# Create fake root PG with all CPUs
# Arguments: list of CPUs
#
sub _pg_create_root
{
	my $pg = ();
	my @cpus = @_;

	$pg->{id} = $ROOT_ID;
	$pg->{ncpus} = scalar @cpus;
	$pg->{util} = 0;
	$pg->{current_rate} = 0;
	$pg->{util_rate_max} = 0;
	$pg->{util_time_running} = 0;
	$pg->{util_time_stopped} = 0;
	$pg->{snaptime} = 0;
	$pg->{generation} = 0;
	$pg->{sh_name} = 'System';
	$pg->{is_leaf} = 0;
	$pg->{cpus} = \@cpus;
	$pg->{parent} = PG_NO_PARENT;

	return ($pg);
}

#
# _pg_all_from_kstats(SNAPSHOT)
# Extract all PG information from kstats
#
sub _pg_all_from_kstats
{
	my $self = shift;
	my $ks = $self->{KSTAT};
	my @all_cpus = @{$self->{CPUS}};

	return unless $ks;

	my $pgtree = ();
	my $pg_info = $ks->{$self->{PG_MODULE}};

	#
	# Walk all PG kstats and copy them to $pgtree->{$id}
	#
	foreach my $id (keys %$pg_info) {
		my $pg_ks = _kstat_get_pg($pg_info, $id,
					  $self->{USE_OLD_KSTATS});
		next unless $pg_ks;

		my $pg = _pg_create_from_kstat($pg_ks, \@all_cpus);

		$pgtree->{$id} = $pg if $pg;
	}

	#
	# OS does not have root PG, so create one.
	#
	if (!$pgtree->{$ROOT_ID}) {
		$pgtree->{$ROOT_ID} = _pg_create_root (@all_cpus);
	}

	#
	# Construct parent-child relationships between PGs
	#

	#
	# Get list of PGs sorted by number of CPUs
	# If two PGs have the same number of CPUs, sort by relationship order.
	#
	my @lineage = sort {
		$a->{ncpus} <=> $b->{ncpus} ||
		_relationship_order($a->{sh_name}) <=>
		_relationship_order($b->{sh_name})
	    } values %$pgtree;

	#
	# For each PG in the lineage discover its parent if it doesn't have one.
	#
	for (my $i = 0; $i < scalar @lineage; $i++) {
		my $pg = $lineage[$i];

		#
		# Ignore PGs which already have parent in kstats
		#
		my $parent = $pg->{parent};
		next if ($parent >= PG_NO_PARENT);

		my $ncpus = $pg->{ncpus};
		my @cpus = @{$pg->{cpus}};

		#
		# Walk the lineage, ignoring any CPUs with the same number of
		# CPUs
		for (my $j = $i + 1; $j < scalar @lineage; $j++) {
			my $pg1 = $lineage[$j];
			my @parent_cpus = @{$pg1->{cpus}};
			if (_is_subset(\@cpus, \@parent_cpus)) {
				$pg->{parent} = $pg1->{id};
				last;
			}
		}
	}

	#
	# Find all top-level PGs and put them under $root
	#
	foreach my $pgid (keys %$pgtree) {
		next if $pgid == $ROOT_ID;
		my $pg = $pgtree->{$pgid};
		$pg->{parent} = $ROOT_ID unless $pg->{parent} >= 0;
	}

	#
	# Now that we know parents, for each parent add all direct children to
	# their parent sets
	#
	foreach my $pg (@lineage) {
		my $parentid = $pg->{parent};
		next unless defined $parentid;

		my $parent = $pgtree->{$parentid};
		push (@{$parent->{children}}, $pg->{id});
	}

	return ($pgtree);
}

#
# Read kstats and initialize PG object
# Collect basic information about cmt_pg
# Add list of children and list of CPUs
# Returns the hash reference indexed by pg id
#
# The _init() function accepts arguments in the form of a hash. The following
# subarguments are supported:
#
#   -cpudata	# Collect per-CPU data from kstats if this is T
#   -tags	# Match PGs to physical relationships if this is T
#   -swload	# Collect software CPU load if this is T

sub _init
{
	my $ks = Sun::Solaris::Kstat->new(strip_strings => 1);
	return unless $ks;

	my %args = @_;
	my $get_cpu_data = $args{-cpudata};
	my $get_tags = $args{-tags};
	my $get_swload = $args{-swload};

	my $self;

	my $use_old_kstat_names = scalar(grep {/^pg_hw_perf/ } keys (%$ks)) == 0;

	my @frequencies;
	$self->{MAX_FREQUENCY} = 0;

	$self->{PG_MODULE} = $use_old_kstat_names ? 'pg' : 'pg_hw_perf';
	$self->{PG_CPU_MODULE} =  $use_old_kstat_names ?
	  'pg_cpu' : 'pg_hw_perf_cpu';
	$self->{USE_OLD_KSTATS} = $use_old_kstat_names;

	$get_cpu_data = 0 unless  scalar(grep {/^$self->{PG_CPU_MODULE}/ }
					 keys (%$ks));

	# Get list of PG-related kstats
	my $pg_keys = $use_old_kstat_names ? 'pg' : 'pg_hw';

	if (scalar(grep { /^$pg_keys/ } keys (%$ks)) == 0) {
		if (exists(&Errno::ENOTSUPP)) {
			$! = &Errno::ENOTSUPP;
		} else {
			$! = 48;
		}
		return;
	}


	#
	# Mapping of cores and chips to CPUs
	#
	my $hw_mapping;

	#
	# Get list of all CPUs
	#
	my $cpu_info = $ks->{cpu_info};

	#
	# @all-cpus is a list of all cpus
	#
	my @all_cpus = keys %$cpu_info;

	#
	# Save list of all CPUs in the snapshot
	#
	$self->{CPUS} = \@all_cpus;

	#
	# Find CPUs for each socket and chip
	# Also while we scan CPU kstats, get maximum frequency of each CPU.
	#
	foreach my $id (@all_cpus) {
		my $ci = $cpu_info->{$id}->{"cpu_info$id"};
		next unless $ci;
		my $core_id = $ci->{core_id};
		my $chip_id = $ci->{chip_id};

		push(@{$hw_mapping->{core}->{$core_id}}, $id)
		  if defined $core_id;
		push(@{$hw_mapping->{chip}->{$chip_id}}, $id)
		  if defined $chip_id;

		# Read CPU frequencies separated by commas
		my $freqs = $ci->{supported_frequencies_Hz};
		my $max_freq = max(split(/:/, $freqs));

		# Calculate maximum frequency for the snapshot.
		$self->{MAX_FREQUENCY} = $max_freq if
		  $self->{MAX_FREQUENCY} < $max_freq;
	}

	$self->{KSTAT} = $ks;

	#
	# Convert kstats to PG tree
	#
	my $pgtree = _pg_all_from_kstats($self);
	$self->{PGTREE} = $pgtree;

	#
	# Find capacity estimate per sharing relationship
	#
	foreach my $pgid (keys %$pgtree) {
		my $pg = $pgtree->{$pgid};
		my $shname = $pg->{sh_name};
		my $max_rate = $pg->{util_rate_max};
		$self->{CAPACITY}->{$shname} = $max_rate if
		  !$self->{CAPACITY}->{$shname} ||
		    $self->{CAPACITY}->{$shname} < $max_rate;
	}

	if ($get_tags) {
		#
		# Walk all PGs and mark all PGs that have corresponding hardware
		# entities (system, chips, cores).
		#
		foreach my $pgid (keys %$pgtree) {
			my $pg = $pgtree->{$pgid};
			my @cpus = @{$pg->{cpus}};
			next unless scalar @cpus > 1;

			if (_set_equal (\@cpus, \@all_cpus)) {
				#
				# PG has all CPUs in the system.
				#
				push (@{$pg->{tags}}, 'system');
			}

			foreach my $name ('core', 'chip') {
				my $hwdata = $hw_mapping->{$name};
				foreach my $id (keys %$hwdata) {
					# CPUs for this entity
					my @hw_cpus = @{$hwdata->{$id}};
					if (_set_equal (\@cpus, \@hw_cpus)) {
						#
						# PG has exactly the same CPUs
						#
						push (@{$pg->{tags}}, $name);
					}
				}
			}
		}
	}

	#
	# Save software load for each CPU
	#
	if ($get_swload) {
		$self->{CPU_LOAD} = _get_sw_cpu_load($ks);
	}

	#
	# Collect per-CPU utilization data if requested
	#
	if ($get_cpu_data) {
		_get_hw_cpu_load($self);
	}

	$self->{GET_CPU_DATA} = $get_cpu_data;

	#
	# Verify that in the end we have the same PG generation for each PG
	#
	if (! _same_generation($self)) {
		$! = &Errno::EAGAIN;
		return;
	}

	return ($self);
}

#
# Verify that topology is the same as at the time snapshot was created
#
sub _same_generation
{
	my $self = shift;
	my $pgtree =  $self->{PGTREE} or return;

	return (0) unless $self;

	my $ks = $self->{KSTAT};
	$ks->update();
	my $pg_info = $ks->{$self->{PG_MODULE}};
	foreach my $id (keys %$pg_info) {
		my $pg = $pgtree->{$id} or next;

		my $pg_ks = _kstat_get_pg($pg_info, $id,
					  $self->{USE_OLD_KSTATS});
		return unless $pg_ks;
		return (0) unless $pg->{generation} == $pg_ks->{generation};
	}
	return (1);
}

#
# Update capacity for both PGs
#
sub _capacity_update
{
	my $c1 = shift;
	my $c2 = shift;

	my $pgtree1 = $c1->{PGTREE};
	my $pgtree2 = $c2->{PGTREE};

	foreach my $pgid (keys %$pgtree1) {
		my $pg1 = $pgtree1->{$pgid};
		my $pg2 = $pgtree2->{$pgid};
		next unless $pg1 && $pg2;
		next unless $pg1->{generation} != $pg2->{generation};
		my $shname1 = $pg1->{sh_name};
		my $shname2 = $pg2->{sh_name};
		next unless $shname1 eq $shname2;
		my $max_rate = max($pg1->{util_rate_max}, $pg2->{util_rate_max});

		my $utilization = abs($pg1->{util} - $pg2->{util});
		my $tdelta = abs($pg1->{snaptime} - $pg2->{snaptime});
		$utilization /= $tdelta if $utilization && $tdelta;
		$max_rate = $utilization if
		  $utilization && $max_rate < $utilization;

		$c1->{CAPACITY}->{$shname1} = $max_rate if
		  !$c1->{CAPACITY}->{$shname1} ||
		    !$c1->{CAPACITY}->{$shname1} < $max_rate;
		$c2->{CAPACITY}->{$shname2} = $max_rate if
		  !$c2->{CAPACITY}->{$shname2} ||
		    !$c2->{CAPACITY}->{$shname2} < $max_rate;
	}
}

#
# Return list of PGs breadth first
#
sub _walk_depth_first
{
	my $p = shift;
	# Nothing to do if list is empty
	return unless scalar (@_);

	return (map { ($_, _walk_depth_first ($p, $p->children($_))) } @_);
}

#
# Return list of PGs breadth first
#
sub _walk_breadth_first
{
	my $p = shift;
	# Nothing to do if list is empty
	return unless scalar (@_);

	return (@_, _walk_breadth_first($p, map { $p->children($_) } @_));
}

#
# Given the kstat reference (already hashed by module name) and PG ID return the
# corresponding kstat.
#
sub _kstat_get_pg
{
	my $mod = shift;
	my $pgid = shift;
	my $use_old_kstats = shift;

	my $id_field = $use_old_kstats ? 'id' : 'pg_id';

	return ($mod->{$pgid}->{hardware}) if $use_old_kstats;

	my @instances = grep { $_->{$id_field} == $pgid }
	  values(%{$mod->{$pgid}});
	return ($instances[0]);
}

######################################################################
# Set routines
#######################################################################
#
# Return T if one list contains all the elements of another list.
# All lists are passed by reference
#
sub _is_subset
{
	my ($left, $right) = @_;
	my %seen;	# Set to 1 for everything in the first list
	# Put the shortest list in $left

	Carp::croak "invalid left argument" unless ref ($left) eq 'ARRAY';
	Carp::croak "invalid right argument" unless ref ($right) eq 'ARRAY';

	# Create a hash indexed by elements in @right with ones as a value.
	map { $seen{$_} = 1 } @$right;

	# Find members of @left not present in @right
	my @extra = grep { !$seen{$_} } @$left;
	return (!scalar(@extra));
}

sub _is_member
{
	my $set = shift;
	my $element = shift;
	my %seen;

	map { $seen{$_} = 1 } @$set;

	return ($seen{$element});
}

#
# Return T if C1 and C2 contain the same elements
#
sub _set_equal
{
	my $c1 = shift;
	my $c2 = shift;

	return 0 unless scalar @$c1 == scalar @$c2;

	return (_is_subset($c1, $c2) && _is_subset($c2, $c1));
}

#
# Return the intersection of two lists passed by reference
# Convert the first list to a hash with seen entries marked as 1-values
# Then grep only elements present in the first list from the second list.
# As a little optimization, use the shorter list to build a hash.
#
sub _set_intersect
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
# Expand start-end into the list of values
# Input: string containing a single numeric ID or x-y range
# Output: single value or a list of values
# Ranges with start being more than end are inverted
#
sub _expand
{
	# Skip the first argument if it is the object reference
	shift if ref $@[0] eq 'HASH';

	my $arg = shift;

	return unless defined $arg;

	my @args = split /,/, $arg;

	return map { _expand($_) } @args if scalar @args > 1;

	$arg = shift @args;
	return unless defined $arg;

	if ($arg =~ m/^\d+$/) {
		# single number
		return ($arg);
	} elsif ($arg =~ m/^(\d+)\-(\d+)$/) {
		my ($start, $end) = ($1, $2);	# $start-$end
		# Reverse the interval if start > end
		($start, $end) = ($end, $start) if $start > $end;
		return ($start .. $end);
	} else {
		return $arg;
	}
	return;
}

#
# Consolidate consecutive ids as start-end
# Input: list of ids
# Output: string with space-sepated cpu values with ranges
#   collapsed as x-y
#
sub _collapse
{
	return ('') unless @_;
	my @args = _uniqsort(@_);
	my $start = shift(@args);
	my $result = '';
	my $end = $start;	# Initial range consists of the first element
	foreach my $el (@args) {
		if (!$el =~ /^\d+$/) {
			$result = "$result $el";
			$end = $el;
		} elsif ($el == ($end + 1)) {
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
	if (! ($end =~ /^\d+$/)) {
		$result = "$result $end";
	} elsif ($end > $start + 1) {
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
# get relationship order from relationship name.
# return 0 for all unknown names.
#
sub _relationship_order
{
	my $name = shift;
	return ($relationships_order{$name} || 0);
}

#
# Get software load for each CPU from kstats
# Argument: kstat reference
# Returns: reference to the hash with 
# cpu_idle, cpu_user, cpu_sys keys.
#
sub _get_sw_cpu_load
{
	my $ks = shift or return;

	my $loads;
	my $sys_ks = $ks->{cpu};
	foreach my $cpu (keys %$sys_ks) {
		my $sys = $sys_ks->{$cpu}->{sys};
		$loads->{$cpu}->{cpu_idle} = $sys->{cpu_ticks_idle};
		$loads->{$cpu}->{cpu_user} = $sys->{cpu_ticks_user};
		$loads->{$cpu}->{cpu_sys} = $sys->{cpu_ticks_kernel};
	}

	return ($loads);
}

#
# Get software load for each CPU from kstats
# Arguments:
#  pgtree reference
#  kstat reference
#
# Returns: nothing
# Stores CPU load in the $pg->{cpudata} hash for each PG
#
sub _get_hw_cpu_load
{
	my $self = shift;
	my $pgtree = $self->{PGTREE};
	my $ks = $self->{KSTAT};

	my $pg_cpu_ks = $ks->{$self->{PG_CPU_MODULE}};

	foreach my $pgid (keys %$pgtree) {
		my $pg = $pgtree->{$pgid};
		my @cpus = @{$pg->{cpus}};
		my $cpu;
		my $pg_id;
		foreach my $cpu (keys %$pg_cpu_ks) {
			next unless _is_member(\@cpus, $cpu);
			my $cpu_hw_data = $pg_cpu_ks->{$cpu};
			foreach my $hw (keys %$cpu_hw_data) {
				my $cpudata = $cpu_hw_data->{$hw};

				#
				# Only consider information for this PG
				#
				next unless $cpudata->{pg_id} == $pgid;

				$pg->{cpudata}->{$cpu}->{generation} =
				  $cpudata->{generation};
				$pg->{cpudata}->{$cpu}->{util} =
				  $cpudata->{hw_util};
				$pg->{cpudata}->{$cpu}->{util_time_running} =
				  $cpudata->{hw_util_time_running};
				$pg->{cpudata}->{$cpu}->{util_time_stopped} =
				  $cpudata->{hw_util_time_stopped};
				$pg->{cpudata}->{$cpu}->{snaptime} =
				  $cpudata->{snaptime};
			}
		}
	}
}

1;

__END__

#
# The information about PG hierarchy is contained in a object return by the
# new() method.
#
# This module can deal with old PG kstats that have 'pg' and 'pg_cpu' as module
# names as well as new PG kstats which use 'pg_hw_perf' and ''pg_hw_perf_cpu' as
# the module name.
#
# The object contains the following fields:
#
#   CPUS		List of all CPUs present.
#   CAPACITY		Estimate of capacity for each sharing
#   PGTREE		The PG tree. See below for the tree representation.
#
#   PG_MODULE 		Module name for the PG kstats. It is either 'pg' for
#			 old style kstats, or 'pg_hw_perf' for new style kstats.
#
#   MAX_FREQUENCY	Maximum CPU frequency
#   USE_OLD_KSTATS	True if we are dealing with old style kstats
#   KSTAT		The kstat object used to generate this hierarchy.
#
# The PG tree is represented as a hash table indexed by PG ID. Each element of
# the table is the hash reference with the following fields:
#
#   children		Reference to the list of children PG IDs
#   cpus		Reference to the list of cpu IDs in the PG
#   current_rate	Current utilization rate
#   generation		PG generation
#   id			PG id
#   ncpus		number of CPUs in the PG
#   parent		PG parent id, or -1 if there is none.
#   sh_name		Sharing name
#   snaptime		Snapshot time
#   util		Hardware utilization
#   util_rate_max	Maximum utilization rate
#   util_time_running	Time (in nanoseconds) when utilization data is collected
#   util_time_stopped	Time when utilization data is not collected
#
# The fields (with the exception of 'children') are a copy of the data from
# kstats.
#
# The PG hierarchy in the kernel does not have the root PG. We simulate the root
# (System) PG which is the parent of top level PGs in the system. This PG always
# has ID 0.
#
