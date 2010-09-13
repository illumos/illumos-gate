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

require 5.8.0;
use strict;
use warnings;

# Make sure that Lgrp test is not executed on anything less than 5.8.0,
# as Lgrp is not implemented there
BEGIN {
	if ($] < 5.008) {
		# Fake one successfull test and exit
		printf "1..1\nok\n";
		exit 0;
	}
}

######################################################################
# Tests for Sun::Solaris::Lgrp API.
#
# This is an example script that demonstrates use of Sun::Solaris::Lgrp module.
# It can be used to test the module itself, the liblgrp library or the in-kernel
# implementation.
######################################################################

#                       Tests to run
use Test::More tests => 33;

# Verify that we can load the module
BEGIN { use_ok('Sun::Solaris::Lgrp') };

use Sun::Solaris::Lgrp ':ALL';

my ($home, $fail);

######################################################################
# Verify that lgrp_init() works.
##
my $c = Sun::Solaris::Lgrp->new(LGRP_VIEW_OS);
ok($c, 'lgrp_init') or die("lgrp_init: $!");
#
######################################################################

######################################################################
# root should have ID 0.
##
my $root = $c->root;
is($root, 0, 'root should have id zero');

#
######################################################################
# Verify lgrp_nlgrps()
##
my $nlgrps = $c->nlgrps;
ok($nlgrps, 'lgrp_nlgrps') or
    diag("lgrp_nlgrps: $!");

my $is_numa = ($nlgrps > 1);

my @lgrps = $c->lgrps;
ok(scalar @lgrps, 'Can get lgrps list') or
    diag("lgrp_lgrps: $!");

is(scalar @lgrps, $nlgrps, 'lgrp_nlgrps() should match number of lgrps');

######################################################################
# All root children should have root as their one and only one parent
##
$fail = 0;
my (@children) = $c->children($root);
my @leaves = $c->leaves;
ok(@leaves, 'There are some leaves');

cmp_ok(@children, '<=', @leaves, 'Root should have nchildren <= nleaves');
my @parents;

foreach my $l (@children) {
    (@parents) = $c->parents($l) or
	diag("lgrp_parents: $!");
    my $nparents = @parents;
    my ($parent, @rest) = @parents;
    $fail++ if $parent != $root;
    $fail++ unless $nparents == 1;
}
is($fail, 0, 'correct parents for children');

######################################################################
# Each lgrp other than root should have a single parent and
# root should have no parents.
##

$fail = 0;
foreach my $l (lgrp_lgrps($c)) {
    next if $l == $root;
    my (@parents) = $c->parents($l) or
	diag("lgrp_parents: $!");
    my $nparents = @parents;
    $fail++ unless $nparents == 1;
}
is($fail, 0, 'All non-leaf lgrps should have single parent');

@parents = $c->parents($root);
ok(!@parents, 'root should have no parents');
#
#######################################################################

######################################################################
# Lgrp affinity tests.
#######################

######################################################################
# lgrp_affinity-set should change home lgrp.
##
SKIP: {
    skip 'Test only valid on NUMA platform', 1 unless $is_numa;
    my $leaf = $leaves[0];	# Pickup any non-root lgrp.
    $home = $c->home(P_PID, P_MYID);

    # Pickup any lgrp not equal to the current one.
    my $lgrp = ($home == $root ? $leaf : $root);
    # Set affinity to the new lgrp.
    $c->affinity_set(P_PID, P_MYID, $lgrp, LGRP_AFF_STRONG) or
	diag("lgrp_affinity_set(): $!");
    # Our home should change to a new lgrp.
    $home = $c->home(P_PID, P_MYID);
    is($home, $lgrp, 'Home lgrp should change after strong affinity is set');
    # Drop affinity to the lgrp.
    $c->affinity_set(P_PID, P_MYID, $lgrp, LGRP_AFF_NONE) or
	diag("lgrp_affinity_set(): $!");
}

######################################################################
# Should be able to set affinity to any legal value
##

my @affs = (LGRP_AFF_WEAK, LGRP_AFF_STRONG, LGRP_AFF_NONE);

foreach my $aff (@affs) {
    $c->affinity_set(P_PID, P_MYID, $root, $aff) or
	diag("lgrp_affinity_set(): $!");
    my $affinity = $c->affinity_get(P_PID, $$, $root);
    is($affinity, $aff, "affinity should be $aff");
}

#
######################################################################

######################################################################
# Root should have non-zero CPUs and memory size
# Also, its memory size should be consistent with the one reported by
# sysconfig.
##
my @rcpus = $c->cpus($root, LGRP_CONTENT_HIERARCHY) or
    die("lgrp_cpus: $!");
my $ncpus = @rcpus;
ok($ncpus, 'there are CPUs in the system');

my $memsize = $c->mem_size($root,
			    LGRP_MEM_SZ_INSTALLED,
			   LGRP_CONTENT_HIERARCHY) or
    diag("lgrp_mem_size(): $!");

ok($memsize, 'memory size is non-zero');
#
######################################################################

######################################################################
# The cookie should not be stale
is($c->stale, 0, 'Cookie should not be stale');
#
######################################################################

######################################################################
# Latency should be non-zero.
my $latency = lgrp_latency($root, $root);
ok(defined $latency, 'lgrp_latency() is working') or
    diag("lgrp_latency: $!");

my $latency1 = $c->latency($root, $root);
ok(defined $latency1, 'lgrp_latency_cookie() is working') or
    diag("lgrp_latency_cookie: $!");

is($latency, $latency1, 'Latencies should match');
#
######################################################################

######################################################################
# Verify latency matrix.
##
SKIP: {
    skip 'Test only valid on NUMA platform', 9 unless $is_numa;

    cmp_ok($latency, '>', 0, "Latency from root to self should be positive");
    my $latencies;
    my $min_latency = 10000;
    my $max_latency = 0;
    my $badlatency = 0;
    my $assymetrical = 0;
    my $diagonalmin = 0;
    my $badself = 0;
    my $nlatencies;

    foreach my $l1 (@lgrps) {
	foreach my $l2 (@lgrps) {
	    $latencies->{$l1}{$l2} = $c->latency($l1, $l2);
	    $nlatencies++ if $latencies->{$l1}{$l2};
	}
    }

    # There should be at least some lgroups which have latencies.
    my @d_lgrps = grep { defined $latencies->{$_}{$_} } @leaves;
    ok(@d_lgrps, 'There should be at least some lgroups which have latencies');

    # All diagonal latencies should be the same.
    my $lat_diag_lgrp = $d_lgrps[0];
    my $lat_diag = $latencies->{$lat_diag_lgrp}{$lat_diag_lgrp};
    my @badlatencies = grep { $latencies->{$_}{$_} != $lat_diag } @d_lgrps;
    is(scalar @badlatencies, 0, 'All diagonal latencies should be the same') or
      diag("diagonal latency: $lat_diag; bad latencies: @badlatencies");

    my %l_cpus;
    my %l_mem;
    my $lgrps_nomem;
    my $lgrps_nocpus;

    foreach my $l1 (@lgrps)  {
	$l_cpus{$l1} = scalar $c->cpus($l1, LGRP_CONTENT_HIERARCHY);
	$l_mem{$l1}  = $c->mem_size($l1, LGRP_MEM_SZ_INSTALLED,
				   LGRP_CONTENT_HIERARCHY);
	$lgrps_nomem++ unless $l_mem{$l1};
	$lgrps_nocpus++ unless $c->cpus($l1, LGRP_CONTENT_HIERARCHY);
    }

    # Verify latencies consistency
    foreach my $l1 (@lgrps) {
	# Can't get latency if source doesn't have CPUs
	next unless $l_cpus{$l1};
	my $self_latency = $latencies->{$l1}{$l1};
	$lat_diag = $self_latency if $self_latency;

	foreach my $l2 (@lgrps) {
	    # Can't get latenciy if destination doesn't have memory
	    next unless $l_mem{$l2};

	    if (! $latencies->{$l1}{$l2}) {
		$badlatency++;
		diag("Invalid latency between $l1 and $l2");
		next;
	    }

	    $max_latency = $latencies->{$l1}{$l2} if 
		$latencies->{$l1}{$l2} > $max_latency;
	    $min_latency = $latencies->{$l1}{$l2} if
		$latencies->{$l1}{$l2} < $min_latency;

	    # Latencies should be symmetrical but only if they are valid.
	    if ($latencies->{$l2}{$l1} &&
		$latencies->{$l1}{$l2} != $latencies->{$l2}{$l1}) {
		$assymetrical++;
		diag("latency($l1, $l2) != latency($l2, $l1)");
	    }

	    $diagonalmin++ if $c->isleaf($l1) && $c->isleaf($l2) &&
		$self_latency && $self_latency > $latencies->{$l1}{$l2};
	}
    }

  SKIP: {
	skip 'Symmetry test only valid if all lgroups have memory and CPUs',
	  1 if $lgrps_nomem || $lgrps_nocpus;
    	is($assymetrical,  0, 'Latencies should be symmetrical');
    }

    is($diagonalmin, 0, 'Latency should be minimal on diagonals');
    is($badlatency, 0, 'Latency should be defined');
    is($max_latency, $latencies->{$root}{$root},
       'Root should have maximum latencies');
    cmp_ok($min_latency, '>', 0, 'Minimum latency should be positive') if
	$nlatencies;
    cmp_ok($min_latency, '<=', $max_latency,
	   'Minimum latency should be less then maximum') if $nlatencies;
}

######################################################################
# Verify lgrp_resources API
##
SKIP: {
    skip 'lgrp_resources() is not supported', 3 if
	((LGRP_VER_CURRENT == 1) || !$is_numa);

    my @lgrps_c = $c->resources($root, LGRP_RSRC_CPU);
    ok(scalar @lgrps_c, 'there are CPU resources in the system');
    $fail = 0;
    my $nc = 0;
    foreach my $l (@lgrps_c) {
	$fail++ unless $c->isleaf($l);
	my @cpu_l = $c->cpus($l, LGRP_CONTENT_DIRECT);
	$nc += @cpu_l;
    }
    is($fail, 0, 'Each lgrp containing CPU resources should be leaf');
    is($nc, $ncpus, 'Number of CPUs should match');
}

#
######################################################################
# THE END!
#########
