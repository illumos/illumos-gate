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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

require 5.8.4;
use strict;
use warnings;
use POSIX;
use File::Basename("basename");

my $cmdname = basename($0);

my $using_scengen = 0;	# 1 if using scenario simulator
my $debug = 0;

my $normal_sleeptime = 10;		# time to sleep between samples
my $idle_sleeptime = 45;		# time to sleep when idle
my $onecpu_sleeptime = (60 * 15);	# used if only 1 CPU on system
my $sleeptime = $normal_sleeptime;	# either normal_ or idle_ or onecpu_

my $idle_intrload = .1;			# idle if interrupt load < 10%

my $timerange_toohi    = .01;
my $statslen = 60;	# time period (in secs) to keep in @deltas


# Parse arguments. intrd does not accept any public arguments; the two
# arguments below are meant for testing purposes. -D generates a significant
# amount of syslog output. -S <filename> loads the filename as a perl
# script. That file is expected to implement a kstat "simulator" which
# can be used to feed information to intrd and verify intrd's responses.

while ($_ = shift @ARGV) {
	if ($_ eq "-S" && $#ARGV != -1) {
		$using_scengen = 1;
		do $ARGV[0];	# load simulator
		shift @ARGV;
	} elsif ($_ eq "-D") {
		$debug = 1;
	}
}

if ($using_scengen == 0) {
	require Sun::Solaris::Kstat;
	require Sun::Solaris::Intrs;
	import Sun::Solaris::Intrs(qw(intrmove is_pcplusmp));
	require Sys::Syslog;
	import Sys::Syslog;
	openlog($cmdname, 'pid', 'daemon');
	setlogmask(Sys::Syslog::LOG_UPTO($debug > 0 ? &Sys::Syslog::LOG_DEBUG :
	    &Sys::Syslog::LOG_INFO));
}

my $asserted = 0;
my $assert_level = 'debug';	# syslog level for assertion failures
sub VERIFY($@)
{
	my $bad = (shift() == 0);	# $_[0] == 0 means assert failed
	if ($bad) {
		my $msg = shift();
		syslog($assert_level, "VERIFY: $msg", @_);
		$asserted++;
	}
	return ($bad);
}




sub getstat($$);
sub generate_delta($$);
sub compress_deltas($);
sub dumpdelta($);

sub goodness($);
sub imbalanced($$);
sub do_reconfig($);

sub goodness_cpu($$);		# private function
sub move_intr($$$$);		# private function
sub ivecs_to_string(@);		# private function
sub do_find_goal($$$$);		# private function
sub find_goal($$);		# private function
sub do_reconfig_cpu2cpu($$$$);	# private function
sub do_reconfig_cpu($$$);	# private function


#
# What follow are the basic data structures routines of intrd.
#
# getstat() is responsible for reading the kstats and generating a "stat" hash.
#
# generate_delta() is responsible for taking two "stat" hashes and creating
# a new "delta" hash that represents what has changed over time.
#
# compress_deltas() is responsible for taking a list of deltas and generating
# a single delta hash that encompasses all the time periods described by the
# deltas.


#
# getstat() is handed a reference to a kstat and generates a hash, returned
# by reference, containing all the fields from the kstats which we need.
# If it returns the scalar 0, it failed to gather the kstats, and the caller
# should react accordingly.
#
# getstat() is also responsible for maintaining a reasonable $sleeptime.
#
# {"snaptime"}          kstat's snaptime
# {<cpuid>}             one hash reference per online cpu
#  ->{"tot"}            == cpu:<cpuid>:sys:cpu_nsec_{user + kernel + idle}
#  ->{"crtime"}         == cpu:<cpuid>:sys:crtime
#  ->{"ivecs"}
#     ->{<cookie#>}     iterates over pci_intrs::<nexus>:cookie
#        ->{"time"}     == pci_intrs:<ivec#>:<nexus>:time (in nsec)
#        ->{"pil"}      == pci_intrs:<ivec#>:<nexus>:pil
#        ->{"crtime"}   == pci_intrs:<ivec#>:<nexus>:crtime
#        ->{"ino"}      == pci_intrs:<ivec#>:<nexus>:ino
#        ->{"num_ino"}  == num inos of single device instance sharing this entry
#				Will be > 1 on pcplusmp X86 systems for devices
#				with multiple MSI interrupts.
#        ->{"buspath"}  == pci_intrs:<ivec#>:<nexus>:buspath
#        ->{"name"}     == pci_intrs:<ivec#>:<nexus>:name
#        ->{"ihs"}      == pci_intrs:<ivec#>:<nexus>:ihs
#

sub getstat($$)
{
	my ($ks, $pcplusmp_sys) = @_;

	my $cpucnt = 0;
	my %stat = ();
	my ($minsnap, $maxsnap);

	# Hash of hash which matches (MSI device, ino) combos to kstats.
	my %msidevs = ();

	# kstats are not generated atomically. Each kstat hierarchy will
	# have been generated within the kernel at a different time. On a
	# thrashing system, we may not run quickly enough in order to get
	# coherent kstat timing information across all the kstats. To
	# determine if this is occurring, $minsnap/$maxsnap are used to
	# find the breadth between the first and last snaptime of all the
	# kstats we access. $maxsnap - $minsnap roughly represents the
	# total time taken up in getstat(). If this time approaches the
	# time between snapshots, our results may not be useful.

	$minsnap = -1;		# snaptime is always a positive number
	$maxsnap = $minsnap;

	# Iterate over the cpus in cpu:<cpuid>::. Check
	# cpu_info:<cpuid>:cpu_info<cpuid>:state to make sure the
	# processor is "on-line". If not, it isn't accepting interrupts
	# and doesn't concern us.
	#
	# Record cpu:<cpuid>:sys:snaptime, and check $minsnap/$maxsnap.

	while (my ($cpu, $cpst) = each %{$ks->{cpu}}) {
		next if !exists($ks->{cpu_info}{$cpu}{"cpu_info$cpu"}{state});
		#"state" fld of kstat w/
		#		  modname    inst name-"cpuinfo0"
		my $state = $ks->{cpu_info}{$cpu}{"cpu_info$cpu"}{state};
		next if ($state !~ /^on-line\0/);
		my $cpu_sys = $cpst->{sys};

		$stat{$cpu}{tot} = ($cpu_sys->{cpu_nsec_idle} +
				    $cpu_sys->{cpu_nsec_user} +
				    $cpu_sys->{cpu_nsec_kernel});
		$stat{$cpu}{crtime} = $cpu_sys->{crtime};
		$stat{$cpu}{ivecs} = {};

		if ($minsnap == -1 || $cpu_sys->{snaptime} < $minsnap) {
			$minsnap = $cpu_sys->{snaptime};
		}
		if ($cpu_sys->{snaptime} > $maxsnap) {
			$maxsnap = $cpu_sys->{snaptime};
		}
		$cpucnt++;
	}

	if ($cpucnt <= 1) {
		$sleeptime = $onecpu_sleeptime;
		return (0);	# nothing to do with 1 CPU
	}

	# Iterate over the ivecs. If the cpu is not on-line, ignore the
	# ivecs mapped to it, if any.
	#
	# Record pci_intrs:{inum}:<nexus>:time, snaptime, crtime, pil,
	# ino, name, and buspath. Check $minsnap/$maxsnap.

	foreach my $inst (values(%{$ks->{pci_intrs}})) {
		my $intrcfg = (values(%$inst))[0]; 
		my $cpu = $intrcfg->{cpu};

		next unless exists $stat{$cpu};
		next if ($intrcfg->{type} =~ /^disabled\0/);

		# Perl looks beyond NULL chars in pattern matching.
		# Truncate name field at the first NULL
		$intrcfg->{name} =~ s/\0.*$//;

		if ($intrcfg->{snaptime} < $minsnap) {
			$minsnap = $intrcfg->{snaptime};
		} elsif ($intrcfg->{snaptime} > $maxsnap) {
			$maxsnap = $intrcfg->{snaptime};
		}

		my $cookie = "$intrcfg->{buspath} $intrcfg->{ino}";
		if (exists $stat{$cpu}{ivecs}{$cookie}) {
			my $cookiestats = $stat{$cpu}{ivecs}{$cookie};

			$cookiestats->{time} += $intrcfg->{time};
			$cookiestats->{name} .= "/$intrcfg->{name}";

			# If this new interrupt sharing $cookie represents a
			# change from an earlier getstat, make sure that
			# generate_delta will see the change by setting
			# crtime to the most recent crtime of its components.

			if ($intrcfg->{crtime} > $cookiestats->{crtime}) {
				$cookiestats->{crtime} = $intrcfg->{crtime};
			}
			$cookiestats->{ihs}++;
			next;
		}
		$stat{$cpu}{ivecs}{$cookie}{time} = $intrcfg->{time};
		$stat{$cpu}{ivecs}{$cookie}{crtime} = $intrcfg->{crtime};
		$stat{$cpu}{ivecs}{$cookie}{pil} = $intrcfg->{pil};
		$stat{$cpu}{ivecs}{$cookie}{ino} = $intrcfg->{ino};
		$stat{$cpu}{ivecs}{$cookie}{num_ino} = 1;
		$stat{$cpu}{ivecs}{$cookie}{buspath} = $intrcfg->{buspath};
		$stat{$cpu}{ivecs}{$cookie}{name} = $intrcfg->{name};
		$stat{$cpu}{ivecs}{$cookie}{ihs} = 1;

		if ($pcplusmp_sys && ($intrcfg->{type} =~ /^msi\0/)) {
			if (!(exists($msidevs{$intrcfg->{name}}))) {
				$msidevs{$intrcfg->{name}} = {};
			}
			$msidevs{$intrcfg->{name}}{$intrcfg->{ino}} =
			    \$stat{$cpu}{ivecs}{$cookie};
		}
	}

	# All MSI interrupts of a device instance share a single MSI address.
	# On X86 systems with an APIC, this MSI address is interpreted as CPU
	# routing info by the APIC.  For this reason, on these platforms, all
	# interrupts for MSI devices must be moved to the same CPU at the same
	# time.
	#
	# Since all interrupts will be on the same CPU on these platforms, all
	# interrupts can be consolidated into one ivec entry.  For such devices,
	# num_ino will be > 1 to denote that a group move is needed.  

	# Loop thru all MSI devices on X86 pcplusmp systems.
	# Nop on other systems.
	foreach my $msidevkey (sort keys %msidevs) {

		# Loop thru inos of the device, sorted by lowest value first
		# For each cookie found for a device, incr num_ino for the
		# lowest cookie and remove other cookies.

		# Assumes PIL is the same for first and current cookies

		my $first_ino = -1;
		my $first_cookiep;
		my $curr_cookiep;
		foreach my $inokey (sort keys %{$msidevs{$msidevkey}}) {
			$curr_cookiep = $msidevs{$msidevkey}{$inokey};
			if ($first_ino == -1) {
				$first_ino = $inokey;
				$first_cookiep = $curr_cookiep;
			} else {
				$$first_cookiep->{num_ino}++;
				$$first_cookiep->{time} +=
				    $$curr_cookiep->{time};
				if ($$curr_cookiep->{crtime} >
				    $$first_cookiep->{crtime}) {
					$$first_cookiep->{crtime} =
					    $$curr_cookiep->{crtime};
				}
				# Invalidate this cookie, less complicated and
				# more efficient than deleting it.
				$$curr_cookiep->{num_ino} = 0;
			}
		}
	}

	# We define the timerange as the amount of time spent gathering the
	# various kstats, divided by our sleeptime. If we take a lot of time
	# to access the kstats, and then we create a delta comparing these
	# kstats with a prior set of kstats, that delta will cover
	# substaintially different amount of time depending upon which
	# interrupt or CPU is being examined.
	#
	# By checking the timerange here, we guarantee that any deltas
	# created from these kstats will contain self-consistent data,
	# in that all CPUs and interrupts cover a similar span of time.
	#
	# $timerange_toohi is the upper bound. Any timerange above
	# this is thrown out as garbage. If the stat is safely within this
	# bound, we treat the stat as representing an instant in time, rather
	# than the time range it actually spans. We arbitrarily choose minsnap
	# as the snaptime of the stat.

	$stat{snaptime} = $minsnap;
	my $timerange = ($maxsnap - $minsnap) / $sleeptime;
	return (0) if ($timerange > $timerange_toohi);	# i.e. failure
	return (\%stat);
}

#
# dumpdelta takes a reference to our "delta" structure:
# {"missing"}           "1" if the delta's component stats had inconsistencies
# {"minsnap"}           time of the first kstat snaptime used in this delta
# {"maxsnap"}           time of the last kstat snaptime used in this delta
# {"goodness"}          cost function applied to this delta
# {"avgintrload"}       avg of interrupt load across cpus, as a percentage
# {"avgintrnsec"}       avg number of nsec spent in interrupts, per cpu
# {<cpuid>}             iterates over on-line cpus
#  ->{"intrs"}          cpu's movable intr time (sum of "time" for each ivec)
#  ->{"tot"}            CPU load from all sources in nsec
#  ->{"bigintr"}        largest value of {ivecs}{<ivec#>}{time} from below
#  ->{"intrload"}       intrs / tot
#  ->{"ivecs"}          
#     ->{<ivec#>}       iterates over ivecs for this cpu
#        ->{"time"}     time used by this interrupt (in nsec)
#        ->{"pil"}      pil level of this interrupt
#        ->{"ino"}      interrupt number (or base vector if MSI group)
#        ->{"buspath"}  filename of the directory of the device's bus
#        ->{"name"}     device name
#        ->{"ihs"}      number of different handlers sharing this ino
#        ->{"num_ino"}  number of interrupt vectors in MSI group
#
# It prints out the delta structure in a nice, human readable display.
#

sub dumpdelta($)
{
	my ($delta) = @_;

	# print global info

	syslog('debug', "dumpdelta:");
	syslog('debug', " RECONFIGURATION IN DELTA") if $delta->{missing} > 0;
	syslog('debug', " avgintrload: %5.2f%%  avgintrnsec: %d",
	       $delta->{avgintrload} * 100, $delta->{avgintrnsec});
	syslog('debug', "    goodness: %5.2f%%", $delta->{goodness} * 100)
	    if exists($delta->{goodness});

	# iterate over cpus

	while (my ($cpu, $cpst) = each %$delta) {
		next if !ref($cpst);		# skip non-cpuid entries
		my $tot = $cpst->{tot};
		syslog('debug', "    cpu %3d intr %7.3f%%  (bigintr %7.3f%%)",
		       $cpu, $cpst->{intrload}*100, $cpst->{bigintr}*100/$tot);
		syslog('debug', "        intrs %d, bigintr %d",
		       $cpst->{intrs}, $cpst->{bigintr});

		# iterate over ivecs on this cpu

		while (my ($ivec, $ivst) = each %{$cpst->{ivecs}}) {
			syslog('debug', "    %15s:\"%s\": %7.3f%%  %d",
			    ($ivst->{ihs} > 1 ? "$ivst->{name}($ivst->{ihs})" :
			    $ivst->{name}), $ivec,
			    $ivst->{time}*100 / $tot, $ivst->{time});
		}
	}
}

#
# generate_delta($stat, $newstat) takes two stat references, returned from
# getstat(), and creates a %delta. %delta (not surprisingly) contains the
# same basic info as stat and newstat, but with the timestamps as deltas
# instead of absolute times. We return a reference to the delta.
#

sub generate_delta($$)
{
	my ($stat, $newstat) = @_;

	my %delta = ();
	my $intrload;
	my $intrnsec;
	my $cpus;

	# Take the worstcase timerange
	$delta{minsnap} = $stat->{snaptime};
	$delta{maxsnap} = $newstat->{snaptime};
	if (VERIFY($delta{maxsnap} > $delta{minsnap},
	    "generate_delta: stats aren't ascending")) {
		$delta{missing} = 1;
		return (\%delta);
	}

	# if there are a different number of cpus in the stats, set missing

	$delta{missing} = (keys(%$stat) != keys(%$newstat));
	if (VERIFY($delta{missing} == 0,
	    "generate_delta: number of CPUs changed")) {
		return (\%delta);
	}

	# scan through every cpu in %newstat and compare against %stat

	while (my ($cpu, $newcpst) = each %$newstat) {
		next if !ref($newcpst);		# skip non-cpuid fields

		# If %stat is missing a cpu from %newstat, then it was just
		# onlined. Mark missing.

		if (VERIFY(exists $stat->{$cpu} &&
		    $stat->{$cpu}{crtime} == $newcpst->{crtime},
		    "generate_delta: cpu $cpu changed")) {
			$delta{missing} = 1;
			return (\%delta);
		}
		my $cpst = $stat->{$cpu};
		$delta{$cpu}{tot} = $newcpst->{tot} - $cpst->{tot};
		if (VERIFY($delta{$cpu}{tot} >= 0,
		    "generate_delta: deltas are not ascending?")) {
			$delta{missing} = 1;
			delete($delta{$cpu});
			return (\%delta);
		}
		# Avoid remote chance of division by zero
		$delta{$cpu}{tot} = 1 if $delta{$cpu}{tot} == 0;
		$delta{$cpu}{intrs} = 0;
		$delta{$cpu}{bigintr} = 0;

		my %ivecs = ();
		$delta{$cpu}{ivecs} = \%ivecs;

		# if the number of ivecs differs, set missing

		if (VERIFY(keys(%{$cpst->{ivecs}}) ==
			   keys(%{$newcpst->{ivecs}}),
			   "generate_delta: cpu $cpu has more/less".
			   " interrupts")) {
			$delta{missing} = 1;
			return (\%delta);
		}

		while (my ($inum, $newivec) = each %{$newcpst->{ivecs}}) {

			# Unused cookie, corresponding to an MSI vector which
			# is part of a group.  The whole group is accounted for
			# by a different cookie.
			next if ($newivec->{num_ino} == 0);

			# If this ivec doesn't exist in $stat, or if $stat
			# shows a different crtime, set missing.
			if (VERIFY(exists $cpst->{ivecs}{$inum} &&
				   $cpst->{ivecs}{$inum}{crtime} ==
				   $newivec->{crtime},
				   "generate_delta: cpu $cpu inum $inum".
				   " has changed")) {
				$delta{missing} = 1;
				return (\%delta);
			}
			my $ivec = $cpst->{ivecs}{$inum};

			# Create $delta{$cpu}{ivecs}{$inum}.

			my %dltivec = ();
			$delta{$cpu}{ivecs}{$inum} = \%dltivec;

			# calculate time used by this interrupt

			my $time = $newivec->{time} - $ivec->{time};
			if (VERIFY($time >= 0,
				   "generate_delta: ivec went backwards?")) {
				$delta{missing} = 1;
				delete($delta{$cpu}{ivecs}{$inum});
				return (\%delta);
			}
			$delta{$cpu}{intrs} += $time;
			$dltivec{time} = $time;
			if ($time > $delta{$cpu}{bigintr}) {
				$delta{$cpu}{bigintr} = $time;
			}

			# Transfer over basic info about the kstat. We
			# don't have to worry about discrepancies between
			# ivec and newivec because we verified that both
			# have the same crtime.

			$dltivec{pil} = $newivec->{pil};
			$dltivec{ino} = $newivec->{ino};
			$dltivec{buspath} = $newivec->{buspath};
			$dltivec{name} = $newivec->{name};
			$dltivec{ihs} = $newivec->{ihs};
			$dltivec{num_ino} = $newivec->{num_ino};
		}
		if ($delta{$cpu}{tot} < $delta{$cpu}{intrs}) {
			# Ewww! Hopefully just a rounding error.
			# Make something up.
			$delta{$cpu}{tot} = $delta{$cpu}{intrs};
		}
		$delta{$cpu}{intrload} =
		       $delta{$cpu}{intrs} / $delta{$cpu}{tot};
		$intrload += $delta{$cpu}{intrload};
		$intrnsec += $delta{$cpu}{intrs};
		$cpus++;
	}
	if ($cpus > 0) {
		$delta{avgintrload} = $intrload / $cpus;
		$delta{avgintrnsec} = $intrnsec / $cpus;
	} else {
		$delta{avgintrload} = 0;
		$delta{avgintrnsec} = 0;
	}
	return (\%delta);
}


# compress_delta takes a list of deltas, and returns a single new delta
# which represents the combined information from all the deltas. The deltas
# provided are assumed to be sequential in time. The resulting compressed
# delta looks just like any other delta. This new delta is also more accurate
# since its statistics are averaged over a longer period than any of the
# original deltas.

sub compress_deltas ($)
{
	my ($deltas) = @_;

	my %newdelta = ();
	my ($intrs, $tot);
	my $cpus = 0;
	my ($high_intrload) = 0;

	if (VERIFY($#$deltas != -1,
		   "compress_deltas: list of delta is empty?")) {
		return (0);
	}
	$newdelta{minsnap} = $deltas->[0]{minsnap};
	$newdelta{maxsnap} = $deltas->[$#$deltas]{maxsnap};
	$newdelta{missing} = 0;

	foreach my $delta (@$deltas) {
		if (VERIFY($delta->{missing} == 0,
		    "compressing bad deltas?")) {
			return (0);
		}
		while (my ($cpuid, $cpu) = each %$delta) {
			next if !ref($cpu);

			$intrs += $cpu->{intrs};
			$tot += $cpu->{tot};
			$newdelta{$cpuid}{intrs} += $cpu->{intrs};
			$newdelta{$cpuid}{tot} += $cpu->{tot};
			if (!exists $newdelta{$cpuid}{ivecs}) {
				my %ivecs = ();
				$newdelta{$cpuid}{ivecs} = \%ivecs;
			}
			while (my ($inum, $ivec) = each %{$cpu->{ivecs}}) {
				my $newivecs = $newdelta{$cpuid}{ivecs};
				$newivecs->{$inum}{time} += $ivec->{time};
				$newivecs->{$inum}{pil} = $ivec->{pil};
				$newivecs->{$inum}{ino} = $ivec->{ino};
				$newivecs->{$inum}{buspath} = $ivec->{buspath};
				$newivecs->{$inum}{name} = $ivec->{name};
				$newivecs->{$inum}{ihs} = $ivec->{ihs};
				$newivecs->{$inum}{num_ino} = $ivec->{num_ino};
			}
		}
	}
	foreach my $cpu (values(%newdelta)) {
		next if !ref($cpu); # ignore non-cpu fields
		$cpus++;

		my $bigintr = 0;
		foreach my $ivec (values(%{$cpu->{ivecs}})) {
			if ($ivec->{time} > $bigintr) {
				$bigintr = $ivec->{time};
			}
		}
		$cpu->{bigintr} = $bigintr;
		$cpu->{intrload} = $cpu->{intrs} / $cpu->{tot};
		if ($high_intrload < $cpu->{intrload}) {
			$high_intrload = $cpu->{intrload};
		}
		$cpu->{tot} = 1 if $cpu->{tot} <= 0;
	}
	if ($cpus == 0) {
		$newdelta{avgintrnsec} = 0;
		$newdelta{avgintrload} = 0;
	} else {
		$newdelta{avgintrnsec} = $intrs / $cpus;
		$newdelta{avgintrload} = $intrs / $tot;
	}
	$sleeptime = ($high_intrload < $idle_intrload) ? $idle_sleeptime :
	    $normal_sleeptime;
	return (\%newdelta);
}





# What follow are the core functions responsible for examining the deltas
# generated above and deciding what to do about them.
#
# goodness() and its helper goodness_cpu() return a heuristic which describe
# how good (or bad) the current interrupt balance is. The value returned will
# be between 0 and 1, with 0 representing maximum goodness, and 1 representing
# maximum badness.
#
# imbalanced() compares a current and historical value of goodness, and
# determines if there has been enough change to warrant evaluating a
# reconfiguration of the interrupts
#
# do_reconfig(), and its helpers, do_reconfig_cpu(), do_reconfig_cpu2cpu(),
# find_goal(), do_find_goal(), and move_intr(), are responsible for examining
# a delta and determining the best possible assignment of interrupts to CPUs.
#
# It is important that do_reconfig() be in alignment with goodness(). If
# do_reconfig were to generate a new interrupt distribution that worsened
# goodness, we could get into a pathological loop with intrd fighting itself,
# constantly deciding that things are imbalanced, and then changing things
# only to make them worse.



# any goodness over $goodness_unsafe_load is considered really bad
# goodness must drop by at least $goodness_mindelta for a reconfig

my $goodness_unsafe_load = .9;
my $goodness_mindelta = .1;

# goodness(%delta) examines a delta and return its "goodness". goodness will
# be between 0 (best) and 1 (major bad). goodness is determined by evaluating
# the goodness of each individual cpu, and returning the worst case. This
# helps on systems with many CPUs, where otherwise a single pathological CPU
# might otherwise be ignored because the average was OK.
#
# To calculate the goodness of an individual CPU, we start by looking at its
# load due to interrupts. If the load is above a certain high threshold and
# there is more than one interrupt assigned to this CPU, we set goodness
# to worst-case. If the load is below the average interrupt load of all CPUs,
# then we return best-case, since what's to complain about?
#
# Otherwise we look at how much the load is above the average, and return
# that as the goodness, with one caveat: we never return more than the CPU's
# interrupt load ignoring its largest single interrupt source. This is
# because a CPU with one high-load interrupt, and no other interrupts, is
# perfectly balanced. Nothing can be done to improve the situation, and thus
# it is perfectly balanced even if the interrupt's load is 100%.

sub goodness($)
{
	my ($delta) = @_;

	return (1) if $delta->{missing} > 0;

	my $high_goodness = 0;
	my $goodness;

	foreach my $cpu (values(%$delta)) {
		next if !ref($cpu);		# skip non-cpuid fields

		$goodness = goodness_cpu($cpu, $delta->{avgintrload});
		if (VERIFY($goodness >= 0 && $goodness <= 1,
			   "goodness: cpu goodness out of range?")) {
			dumpdelta($delta);
			return (1);
		}
		if ($goodness == 1) {
			return (1);	# worst case, no need to continue
		}
		if ($goodness > $high_goodness) {
			$high_goodness = $goodness;
		}
	}
	return ($high_goodness);
}

sub goodness_cpu($$)		# private function
{
	my ($cpu, $avgintrload) = @_;

	my $goodness;
	my $load = $cpu->{intrs} / $cpu->{tot};

	return (0) if ($load < $avgintrload);	# low loads are perfectly good

	# Calculate $load_no_bigintr, which represents the load
	# due to interrupts, excluding the one biggest interrupt.
	# This is the most gain we can get on this CPU from
	# offloading interrupts.

	my $load_no_bigintr = ($cpu->{intrs} - $cpu->{bigintr}) / $cpu->{tot};

	# A major imbalance is indicated if a CPU is saturated
	# with interrupt handling, and it has more than one
	# source of interrupts. Those other interrupts could be
	# starved if of a lower pil. Return a goodness of 1,
	# which is the worst possible return value,
	# which will effectively contaminate this entire delta.

	my $cnt = keys(%{$cpu->{ivecs}});

	if ($load > $goodness_unsafe_load && $cnt > 1) {
		return (1);
	}
	$goodness = $load - $avgintrload;
	if ($goodness > $load_no_bigintr) {
		$goodness = $load_no_bigintr;
	}
	return ($goodness);
}


# imbalanced() is used by the main routine to determine if the goodness
# has shifted far enough from our last baseline to warrant a reassignment
# of interrupts. A very high goodness indicates that a CPU is way out of
# whack. If the goodness has varied too much since the baseline, then
# perhaps a reconfiguration is worth considering.

sub imbalanced ($$)
{
	my ($goodness, $baseline) = @_;

	# Return 1 if we are pathological, or creeping away from the baseline

	return (1) if $goodness > .50;
	return (1) if abs($goodness - $baseline) > $goodness_mindelta;
	return (0);
}

# do_reconfig(), do_reconfig_cpu(), and do_reconfig_cpu2cpu(), are the
# decision-making functions responsible for generating a new interrupt
# distribution. They are designed with the definition of goodness() in
# mind, i.e. they use the same definition of "good distribution" as does
# goodness().
#
# do_reconfig() is responsible for deciding whether a redistribution is
# actually warranted. If the goodness is already pretty good, it doesn't
# waste the CPU time to generate a new distribution. If it
# calculates a new distribution and finds that it is not sufficiently
# improved from the prior distirbution, it will not do the redistribution,
# mainly to avoid the disruption to system performance caused by
# rejuggling interrupts.
#
# Its main loop works by going through a list of cpus sorted from
# highest to lowest interrupt load. It removes the highest-load cpus
# one at a time and hands them off to do_reconfig_cpu(). This function
# then re-sorts the remaining CPUs from lowest to highest interrupt load,
# and one at a time attempts to rejuggle interrupts between the original
# high-load CPU and the low-load CPU. Rejuggling on a high-load CPU is
# considered finished as soon as its interrupt load is within
# $goodness_mindelta of the average interrupt load. Such a CPU will have
# a goodness of below the $goodness_mindelta threshold.

#
# move_intr(\%delta, $inum, $oldcpu, $newcpu)
# used by reconfiguration code to move an interrupt between cpus within
# a delta. This manipulates data structures, and does not actually move
# the interrupt on the running system.
#
sub move_intr($$$$)		# private function
{
	my ($delta, $inum, $oldcpuid, $newcpuid) = @_;

	my $ivec = $delta->{$oldcpuid}{ivecs}{$inum};

	# Remove ivec from old cpu

	my $oldcpu = $delta->{$oldcpuid};
	$oldcpu->{intrs} -= $ivec->{time};
	$oldcpu->{intrload} = $oldcpu->{intrs} / $oldcpu->{tot};
	delete($oldcpu->{ivecs}{$inum});

	VERIFY($oldcpu->{intrs} >= 0, "move_intr: intr's time > total time?");
	VERIFY($ivec->{time} <= $oldcpu->{bigintr},
	       "move_intr: intr's time > bigintr?");

	if ($ivec->{time} >= $oldcpu->{bigintr}) {
		my $bigtime = 0;

		foreach my $ivec (values(%{$oldcpu->{ivecs}})) {
			$bigtime = $ivec->{time} if $ivec->{time} > $bigtime;
		}
		$oldcpu->{bigintr} = $bigtime;
	}

	# Add ivec onto new cpu

	my $newcpu = $delta->{$newcpuid};

	$ivec->{nowcpu} = $newcpuid;
	$newcpu->{intrs} += $ivec->{time};
	$newcpu->{intrload} = $newcpu->{intrs} / $newcpu->{tot};
	$newcpu->{ivecs}{$inum} = $ivec;

	$newcpu->{bigintr} = $ivec->{time}
		if $ivec->{time} > $newcpu->{bigintr};
}

sub move_intr_check($$$)	# private function
{
	my ($delta, $oldcpuid, $newcpuid) = @_;

	VERIFY($delta->{$oldcpuid}{tot} >= $delta->{$oldcpuid}{intrs},
	       "Moved interrupts left 100+%% load on src cpu");
	VERIFY($delta->{$newcpuid}{tot} >= $delta->{$newcpuid}{intrs},
	       "Moved interrupts left 100+%% load on tgt cpu");
}

sub ivecs_to_string(@)		# private function
{
	my $str = "";
	foreach my $ivec (@_) {
		$str = "$str $ivec->{inum}";
	}
	return ($str);
}


sub do_reconfig($)
{
	my ($delta) = @_;

	my $goodness = $delta->{goodness};

	# We can't improve goodness to better than 0. We should stop here
	# if, even if we achieve a goodness of 0, the improvement is still
	# too small to merit the action.

	if ($goodness - 0 < $goodness_mindelta) {
		syslog('debug', "goodness good enough, don't reconfig");
		return (0);
	}

	syslog('notice', "Optimizing interrupt assignments");

	if (VERIFY ($delta->{missing} == 0, "RECONFIG Aborted: should not ".
	    "have a delta with missing")) {
		return (-1);
	}

	# Make a list of all cpuids, and also add some extra information
	# to the ivec structures.

	my @cpusortlist = ();

	while (my ($cpuid, $cpu) = each %$delta) {
		next if !ref($cpu);	# skip non-cpu entries

		push(@cpusortlist, $cpuid);
		while (my ($inum, $ivec) = each %{$cpu->{ivecs}}) {
			$ivec->{origcpu} = $cpuid;
			$ivec->{nowcpu} = $cpuid;
			$ivec->{inum} = $inum;
		}
	}

	# Sort the list of CPUs from highest to lowest interrupt load.
	# Remove the top CPU from that list and attempt to redistribute
	# its interrupts. If the CPU has a goodness below a threshold,
	# just ignore the CPU and move to the next one. If the CPU's
	# load falls below the average load plus that same threshold,
	# then there are no CPUs left worth reconfiguring, and we're done.

	while (@cpusortlist) {
		# Re-sort cpusortlist each time, since do_reconfig_cpu can
		# move interrupts around.

		@cpusortlist =
		    sort({$delta->{$b}{intrload} <=> $delta->{$a}{intrload}}
		    @cpusortlist);

		my $cpu = shift(@cpusortlist);
		if (($delta->{$cpu}{intrload} <= $goodness_unsafe_load) &&
		    ($delta->{$cpu}{intrload} <=
		    $delta->{avgintrload} + $goodness_mindelta)) {
			syslog('debug', "finished reconfig: cpu $cpu load ".
			    "$delta->{$cpu}{intrload} avgload ".
			    "$delta->{avgintrload}");
			last;
		}
		if (goodness_cpu($delta->{$cpu}, $delta->{avgintrload}) <
		    $goodness_mindelta) {
			next;
		}
		do_reconfig_cpu($delta, \@cpusortlist, $cpu);
	}

	# How good a job did we do? If the improvement was minimal, and
	# our goodness wasn't pathological (and thus needing any help it
	# can get), then don't bother moving the interrupts.

	my $newgoodness = goodness($delta);
	VERIFY($newgoodness <= $goodness,
	       "reconfig: result has worse goodness?");

	if (($goodness != 1 || $newgoodness == 1) &&
	    $goodness - $newgoodness < $goodness_mindelta) {
		syslog('debug', "goodness already near optimum, ".
		       "don't reconfig");
		return (0);
	}
	syslog('debug', "goodness %5.2f%% --> %5.2f%%", $goodness*100,
	       $newgoodness*100);

	# Time to move those interrupts!

	my $ret = 1;
	my $warned = 0;
	while (my ($cpuid, $cpu) = each %$delta) {
		next if $cpuid =~ /\D/;
		while (my ($inum, $ivec) = each %{$cpu->{ivecs}}) {
			next if ($ivec->{origcpu} == $cpuid);

			if (!intrmove($ivec->{buspath}, $ivec->{ino},
			    $cpuid, $ivec->{num_ino})) {
				syslog('warning', "Unable to move interrupts")
				    if $warned++ == 0;
				syslog('debug', "Unable to move buspath ".
				    "$ivec->{buspath} ino $ivec->{ino} to ".
				    "cpu $cpuid");
				$ret = -1;
			}
		}
	}

	syslog('notice', "Interrupt assignments optimized");
	return ($ret);
}

sub do_reconfig_cpu($$$)	# private function
{
	my ($delta, $cpusortlist, $oldcpuid) = @_;

	# We have been asked to rejuggle interrupts between $oldcpuid and
	# other CPUs found on $cpusortlist so as to improve the load on
	# $oldcpuid. We reverse $cpusortlist to get our own copy of the
	# list, sorted from lowest to highest interrupt load. One at a
	# time, shift a CPU off of this list of CPUs, and attempt to
	# rejuggle interrupts between the two CPUs. Don't do this if the
	# other CPU has a higher load than oldcpuid. We're done rejuggling
	# once $oldcpuid's goodness falls below a threshold.

	syslog('debug', "reconfiguring $oldcpuid");

	my $cpu = $delta->{$oldcpuid};
	my $avgintrload = $delta->{avgintrload};

	my @cputargetlist = reverse(@$cpusortlist); # make a copy of the list
	while ($#cputargetlist != -1) {
 		last if goodness_cpu($cpu, $avgintrload) < $goodness_mindelta;

		my $tgtcpuid = shift(@cputargetlist);
		my $tgt = $delta->{$tgtcpuid};
		my $load = $cpu->{intrload};
		my $tgtload = $tgt->{intrload};
		last if $tgtload > $load;
		do_reconfig_cpu2cpu($delta, $oldcpuid, $tgtcpuid, $load);
	}
}

sub do_reconfig_cpu2cpu($$$$)	# private function
{
	my ($delta, $srccpuid, $tgtcpuid, $srcload) = @_;

	# We've been asked to consider interrupt juggling between srccpuid
	# (with a high interrupt load) and tgtcpuid (with a lower interrupt
	# load). First, make a single list with all of the ivecs from both
	# CPUs, and sort the list from highest to lowest load.

	syslog('debug', "exchanging intrs between $srccpuid and $tgtcpuid");

	# Gather together all the ivecs and sort by load

	my @ivecs = (values(%{$delta->{$srccpuid}{ivecs}}),
	    values(%{$delta->{$tgtcpuid}{ivecs}}));
	return if $#ivecs == -1;

	@ivecs = sort({$b->{time} <=> $a->{time}} @ivecs);

	# Our "goal" load for srccpuid is the average load across all CPUs.
	# find_goal() will find determine the optimum selection of the
	# available interrupts which comes closest to this goal without
	# falling below the goal.

	my $goal = $delta->{avgintrnsec};

	# We know that the interrupt load on tgtcpuid is less than that on
	# srccpuid, but its load could still be above avgintrnsec. Don't
	# choose a goal which would bring srccpuid below the load on tgtcpuid.

	my $avgnsec =
	    ($delta->{$srccpuid}{intrs} + $delta->{$tgtcpuid}{intrs}) / 2;
	if ($goal < $avgnsec) {
		$goal = $avgnsec;
	}

	# If the largest of the interrupts is on srccpuid, leave it there.
	# This can help minimize the disruption caused by moving interrupts.

	if ($ivecs[0]->{origcpu} == $srccpuid) {
		syslog('debug', "Keeping $ivecs[0]->{inum} on $srccpuid");
		$goal -= $ivecs[0]->{time};
		shift(@ivecs);
	}

	syslog('debug', "GOAL: inums should total $goal");
	find_goal(\@ivecs, $goal);

	# find_goal() returned its results to us by setting $ivec->{goal} if
	# the ivec should be on srccpuid, or clearing it for tgtcpuid.
	# Call move_intr() to update our $delta with the new results.

	foreach my $ivec (@ivecs) {
		syslog('debug', "ivec $ivec->{inum} goal $ivec->{goal}");
		VERIFY($ivec->{nowcpu} == $srccpuid ||
		    $ivec->{nowcpu} == $tgtcpuid, "cpu2cpu found an ".
		    "interrupt not currently on src or tgt cpu");

		if ($ivec->{goal} && $ivec->{nowcpu} != $srccpuid) {
			move_intr($delta, $ivec->{inum}, $ivec->{nowcpu},
			    $srccpuid);
		} elsif ($ivec->{goal} == 0 && $ivec->{nowcpu} != $tgtcpuid) {
			move_intr($delta, $ivec->{inum}, $ivec->{nowcpu},
			    $tgtcpuid);
		}
	}
	move_intr_check($delta, $srccpuid, $tgtcpuid); # asserts

	my $newload = $delta->{$srccpuid}{intrs} / $delta->{$srccpuid}{tot};
	VERIFY($newload <= $srcload && $newload > $delta->{avgintrload},
	    "cpu2cpu: new load didn't end up in expected range");
}


# find_goal() and its helper do_find_goal() are used to find the best
# combination of interrupts in order to generate a load that is as close
# as possible to a goal load without falling below that goal. Before returning
# to its caller, find_goal() sets a new value in the hash of each interrupt,
# {goal}, which if set signifies that this interrupt is one of the interrupts
# identified as part of the set of interrupts which best meet the goal.
#
# The arguments to find_goal are a list of ivecs (hash references), sorted
# by descending {time}, and the goal load. The goal is relative to {time}.
# The best fit is determined by performing a depth-first search. do_find_goal
# is the recursive subroutine which carries out the search.
#
# It is passed an index as an argument, originally 0. On a given invocation,
# it is only to consider interrupts in the ivecs array starting at that index.
# It then considers two possibilities:
#   1) What is the best goal-fit if I include ivecs[index]?
#   2) What is the best goal-fit if I exclude ivecs[index]?
# To determine case 1, it subtracts the load of ivecs[index] from the goal,
# and calls itself recursively with that new goal and index++.
# To determine case 2, it calls itself recursively with the same goal and
# index++.
#
# It then compares the two results, decide which one best meets the goals,
# and returns the result. The return value is the best-fit's interrupt load,
# followed by a list of all the interrupts which make up that best-fit.
#
# As an optimization, a second array loads[] is created which mirrors ivecs[].
# loads[i] will equal the total loads of all ivecs[i..$#ivecs]. This is used
# by do_find_goal to avoid recursing all the way to the end of the ivecs
# array if including all remaining interrupts will still leave the best-fit
# at below goal load. If so, it then includes all remaining interrupts on
# the goal list and returns.
#
sub find_goal($$)		# private function
{
	my ($ivecs, $goal) = @_;

	my @goals;
	my $load;
	my $ivec;

	if ($goal <= 0) {
		@goals = ();	# the empty set will best meet the goal
	} else {
		syslog('debug', "finding goal from intrs %s",
		    ivecs_to_string(@$ivecs));

		# Generate @loads array

		my $tot = 0;
		foreach $ivec (@$ivecs) {
			$tot += $ivec->{time};
		}
		my @loads = ();
		foreach $ivec (@$ivecs) {
			push(@loads, $tot);
			$tot -= $ivec->{time};
		}
		($load, @goals) = do_find_goal($ivecs, \@loads, $goal, 0);
		VERIFY($load >= $goal, "find_goal didn't meet goals");
	}
	syslog('debug', "goals found: %s", ivecs_to_string(@goals));

	# Set or clear $ivec->{goal} for each ivec, based on returned @goals

	foreach $ivec (@$ivecs) {
		if ($#goals > -1 && $ivec == $goals[0]) {
			syslog('debug', "inum $ivec->{inum} on source cpu");
			$ivec->{goal} = 1;
			shift(@goals);
		} else {
			syslog('debug', "inum $ivec->{inum} on target cpu");
			$ivec->{goal} = 0;
		}
	}
}


sub do_find_goal($$$$)		# private function
{
	my ($ivecs, $loads, $goal, $idx) = @_;

	if ($idx > $#{$ivecs}) {
		return (0);
	}
	syslog('debug', "$idx: finding goal $goal inum $ivecs->[$idx]{inum}");

	my $load = $ivecs->[$idx]{time};
	my @goals_with = ();
	my @goals_without = ();
	my ($with, $without);

	# If we include all remaining items and we're still below goal,
	# stop here. We can just return a result that includes $idx and all
	# subsequent ivecs. Since this will still be below goal, there's
	# nothing better to be done.

	if ($loads->[$idx] <= $goal) {
		syslog('debug',
		    "$idx: including all remaining intrs %s with load %d",
		    ivecs_to_string(@$ivecs[$idx .. $#{$ivecs}]),
		    $loads->[$idx]);
		return ($loads->[$idx], @$ivecs[$idx .. $#{$ivecs}]);
	}

	# Evaluate the "with" option, i.e. the best matching goal which
	# includes $ivecs->[$idx]. If idx's load is more than our goal load,
	# stop here. Once we're above the goal, there is no need to consider
	# further interrupts since they'll only take us further from the goal.

	if ($goal <= $load) {
		$with = $load;	# stop here
	} else {
		($with, @goals_with) =
		    do_find_goal($ivecs, $loads, $goal - $load, $idx + 1);
		$with += $load;
	}
	syslog('debug', "$idx: with-load $with intrs %s",
	       ivecs_to_string($ivecs->[$idx], @goals_with));

	# Evaluate the "without" option, i.e. the best matching goal which
	# excludes $ivecs->[$idx].

	($without, @goals_without) =
	    &do_find_goal($ivecs, $loads, $goal, $idx + 1);
	syslog('debug', "$idx: without-load $without intrs %s",
	       ivecs_to_string(@goals_without));

	# We now have our "with" and "without" options, and we choose which
	# best fits the goal. If one is greater than goal and the other is
	# below goal, we choose the one that is greater. If they are both 
	# below goal, then we choose the one that is greater. If they are
	# both above goal, then we choose the smaller.

	my $which;		# 0 == with, 1 == without
	if ($with >= $goal && $without < $goal) {
		$which = 0;
	} elsif ($with < $goal && $without >= $goal) {
		$which = 1;
	} elsif ($with >= $goal && $without >= $goal) {
		$which = ($without < $with);
	} else {
		$which = ($without > $with);
	}

	# Return the load of our best case scenario, followed by all the ivecs
	# which compose that goal.

	if ($which == 1) {	# without
		syslog('debug', "$idx: going without");
		return ($without, @goals_without);
	} else {
		syslog('debug', "$idx: going with");
		return ($with, $ivecs->[$idx], @goals_with);
	}
	# Not reached
}




syslog('debug', "intrd is starting".($debug ? " (debug)" : ""));

my @deltas = ();
my $deltas_tottime = 0;		# sum of maxsnap-minsnap across @deltas
my $avggoodness;
my $baseline_goodness = 0;
my $compdelta;

my $do_reconfig;

# temp variables
my $goodness;
my $deltatime;
my $olddelta;
my $olddeltatime;
my $delta;
my $newstat;
my $below_statslen;
my $newtime;
my $ret;


my $gotsig = 0;
$SIG{INT} = sub { $gotsig = 1; };     # don't die in the middle of retargeting
$SIG{HUP} = $SIG{INT};
$SIG{TERM} = $SIG{INT};

my $ks;
if ($using_scengen == 0) {
	$ks = Sun::Solaris::Kstat->new();
} else {
	$ks = myks_update();	# supplied by the simulator
}

# If no pci_intrs kstats were found, we need to exit, but we can't because
# SMF will restart us and/or report an error to the administrator. But
# there's nothing an administrator can do. So print out a message for SMF
# logs and silently pause forever.

if (!exists($ks->{pci_intrs})) {
	print STDERR "$cmdname: no interrupts were found; ".
	    "your PCI bus may not yet be supported\n";
	pause() while $gotsig == 0;
	exit 0;
}

# See if this is a system with a pcplusmp APIC.
# Such systems will get special handling.
# Assume that if one bus has a pcplusmp APIC that they all do.

# Get a list of pci_intrs kstats.
my @elem = values(%{$ks->{pci_intrs}});
my $elem0 = $elem[0];
my $elemval = (values(%$elem0))[0];

# Use its buspath to query the system.  It is assumed that either all or none
# of the busses on a system are hosted by the pcplusmp APIC.
my $pcplusmp_sys = is_pcplusmp($elemval->{buspath});

my $stat = getstat($ks, $pcplusmp_sys);

for (;;) {
	sub clear_deltas {
		@deltas = ();
		$deltas_tottime = 0;
		$stat = 0;   # prevent next gen_delta() from setting {missing}
	}

	# 1. Sleep, update the kstats, and save the new stats in $newstat.

	exit 0 if $gotsig;		# if we got ^C / SIGTERM, exit
	if ($using_scengen == 0) {
		sleep($sleeptime);
		exit 0 if $gotsig;	# if we got ^C / SIGTERM, exit
		$ks->update();
	} else {
		$ks = myks_update();
	}
	$newstat = getstat($ks, $pcplusmp_sys);

	# $stat or $newstat could be zero if they're uninitialized, or if
	# getstat() failed. If $stat is zero, move $newstat to $stat, sleep
	# and try again. If $newstat is zero, then we also sleep and try
	# again, hoping the problem will clear up.

	next if (!ref $newstat);
	if (!ref $stat) {
		$stat = $newstat;
		next;
	}

	# 2. Compare $newstat with the prior set of values, result in %$delta.

	$delta = generate_delta($stat, $newstat);
	dumpdelta($delta) if $debug;	# Dump most recent stats to stdout.
	$stat = $newstat;	# The new stats now become the old stats.


	# 3. If $delta->{missing}, then there has been a reconfiguration of
	# either cpus or interrupts (probably both). We need to toss out our
	# old set of statistics and start from scratch.
	#
	# Also, if the delta covers a very long range of time, then we've
	# been experiencing a system overload that has resulted in intrd
	# not being allowed to run effectively for a while now. As above,
	# toss our old statistics and start from scratch.

	$deltatime = $delta->{maxsnap} - $delta->{minsnap};
	if ($delta->{missing} > 0 || $deltatime > $statslen) {
		clear_deltas();
		syslog('debug', "evaluating interrupt assignments");
		next;
	}


	# 4. Incorporate new delta into the list of deltas, and associated
	# statistics. If we've just now received $statslen deltas, then it's
	# time to evaluate a reconfiguration.

	$below_statslen = ($deltas_tottime < $statslen);
	$deltas_tottime += $deltatime;
	$do_reconfig = ($below_statslen && $deltas_tottime >= $statslen);
	push(@deltas, $delta);

	# 5. Remove old deltas if total time is more than $statslen. We use
	# @deltas as a moving average of the last $statslen seconds. Shift
	# off the olders deltas, but only if that doesn't cause us to fall
	# below $statslen seconds.

	while (@deltas > 1) {
		$olddelta = $deltas[0];
		$olddeltatime = $olddelta->{maxsnap} - $olddelta->{minsnap};
		$newtime = $deltas_tottime - $olddeltatime;
		last if ($newtime < $statslen);

		shift(@deltas);
		$deltas_tottime = $newtime;
	}

	# 6. The brains of the operation are here. First, check if we're
	# imbalanced, and if so set $do_reconfig. If $do_reconfig is set,
	# either because of imbalance or above in step 4, we evaluate a
	# new configuration.
	#
	# First, take @deltas and generate a single "compressed" delta
	# which summarizes them all. Pass that to do_reconfig and see
	# what it does with it:
	#
	# $ret == -1 : failure
	# $ret ==  0 : current config is optimal (or close enough)
	# $ret ==  1 : reconfiguration has occurred
	#
	# If $ret is -1 or 1, dump all our deltas and start from scratch.
	# Step 4 above will set do_reconfig soon thereafter.
	#
	# If $ret is 0, then nothing has happened because we're already
	# good enough. Set baseline_goodness to current goodness.

	$compdelta = compress_deltas(\@deltas);
	if (VERIFY(ref($compdelta) eq "HASH", "couldn't compress deltas")) {
		clear_deltas();
		next;
	}
	$compdelta->{goodness} = goodness($compdelta);
	dumpdelta($compdelta) if $debug;

	$goodness = $compdelta->{goodness};
	syslog('debug', "GOODNESS: %5.2f%%", $goodness * 100);

	if ($deltas_tottime >= $statslen &&
	    imbalanced($goodness, $baseline_goodness)) {
		$do_reconfig = 1;
	}

	if ($do_reconfig) {
		$ret = do_reconfig($compdelta);

		if ($ret != 0) {
			clear_deltas();
			syslog('debug', "do_reconfig FAILED!") if $ret == -1;
		} else {
			syslog('debug', "setting new baseline of $goodness");
			$baseline_goodness = $goodness;
		}
	}
	syslog('debug', "---------------------------------------");
}		
