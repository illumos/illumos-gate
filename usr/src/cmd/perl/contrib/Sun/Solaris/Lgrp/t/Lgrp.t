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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Tests for Sun::Solaris::Lgrp API.
#
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lgrp.t'
#
# The test uses Test module which is available on Perl 5.6 and later.
#


use strict;
use warnings;
use Test;

# Tests to run
BEGIN { plan tests => 63 }

use Sun::Solaris::Lgrp ':ALL';

#
######################################################################

my ($home, $fail);

######################################################################
# Check that all exported constants can be accessed.
$fail = 0;
foreach my $constname (qw(
	LGRP_AFF_NONE LGRP_AFF_STRONG LGRP_AFF_WEAK LGRP_CONTENT_DIRECT
	LGRP_CONTENT_HIERARCHY LGRP_MEM_SZ_FREE
	LGRP_MEM_SZ_INSTALLED LGRP_VER_CURRENT LGRP_VER_NONE
	LGRP_VIEW_CALLER LGRP_VIEW_OS LGRP_RSRC_CPU LGRP_RSRC_MEM
	LGRP_CONTENT_ALL LGRP_LAT_CPU_TO_MEM)) {
  next if (eval "my \$a = $constname; 1");
  $fail++;
}

ok($fail,  0, 'All Constants defined' );

#########################

######################################################################
# Verify lgrp_version
##
my $version = lgrp_version(-1);
ok($version, LGRP_VER_NONE, 'incorrect lgrp version unsupported');

$version = lgrp_version(LGRP_VER_NONE);
ok($version, LGRP_VER_CURRENT, 'lgrp version is current');

$version = lgrp_version(LGRP_VER_CURRENT);
ok($version, LGRP_VER_CURRENT, 'support LGRP_VER_CURRENT version');
#
#######################################################################

######################################################################
# Verify that lgrp_init()/lgrp_fini work.
##
my $c = lgrp_init(LGRP_VIEW_CALLER);
ok($c) or
    die("lgrp_init: $!");

my $view = lgrp_view($c);

ok($view, LGRP_VIEW_CALLER, 'View is LGRP_VIEW_CALLER');

my $fin = lgrp_fini($c);
ok($fin);

# Try to free it again, it should fail.
$fin = lgrp_fini($c);
ok($fin, undef, 'lgrp_fini second time should fail');

$c = lgrp_init(LGRP_VIEW_OS);
ok($c) or
    die("lgrp_init: $!");

$view = lgrp_view($c);

ok($view, LGRP_VIEW_OS, 'View is LGRP_VIEW_OS');
#
######################################################################

######################################################################
# root should have ID 0.
##
my $root = lgrp_root($c);
ok($root, 0, 'root should have id zero');
#
######################################################################
# Verify lgrp_nlgrps()
##
my $nlgrps = lgrp_nlgrps($c);
ok($nlgrps);

my @lgrps = lgrp_lgrps($c);
ok(@lgrps);
ok(scalar @lgrps, $nlgrps, 'lgrp_nlgrps() should match number of lgrps');
ok($nlgrps, lgrp_lgrps($c), 'lgrp_lgrps() in scalar context is sane');

######################################################################
# All root children should have root as their one and only one parent
##
$fail = 0;
my @children = lgrp_children($c, $root);
ok(scalar @children, lgrp_children($c, $root), 'lgrp_children as scalar');
my @leaves = lgrp_leaves $c;
ok(scalar @leaves);
ok(scalar @leaves, lgrp_leaves $c);
ok(scalar @children <= scalar @leaves);

my @parents;

my $fail_lgrp_parents = 0;

foreach my $l (@children) {
    @parents = lgrp_parents($c, $l) or
	(print STDERR "# lgrp_parents: $!\n"), $fail++, last;
    my $nparents = @parents;
    my ($parent, @rest) = @parents;
    $fail++ if $parent != $root;
    $fail++ unless $nparents == 1;
    $fail_lgrp_parents++ if $nparents != lgrp_parents($c, $l);
}
ok($fail, 0, 'correct parents for children');
ok($fail_lgrp_parents, 0, 'correct lgrp_parents() as scalar');

######################################################################
# Illegal parents have no children
##
@children = lgrp_children($c, -1);
my $nchildren = lgrp_children($c, -1);
ok(scalar @children, 0, 'Illegal parents have no children');
# Same in scalar context
ok($nchildren, undef, 'No children means undef as scalar');

######################################################################
# root should have no parents.
##
@parents = lgrp_parents($c, $root);
ok(scalar @parents, 0, 'root should have no parents');
# Same in scalar context
ok(lgrp_parents($c, $root), 0);
#
######################################################################
# Illegal children have no paremts
##
@parents = lgrp_parents($c, -1);
my $nparents = lgrp_parents($c, -1);
ok(scalar @parents, 0, 'Illegal children have no paremts');
# Same in scalar context
ok($nparents, undef, 'No parents means undef as scalar');
#
######################################################################
# Root should have non-zero CPUs and memory size
##
my @cpus = lgrp_cpus($c, $root, LGRP_CONTENT_HIERARCHY);
my $ncpus = lgrp_cpus($c, $root, LGRP_CONTENT_HIERARCHY);
ok(scalar @cpus, $ncpus);
ok($ncpus);
ok(lgrp_mem_size($c, $root, LGRP_MEM_SZ_INSTALLED, LGRP_CONTENT_HIERARCHY));
my @ncpus_bad = lgrp_cpus($c, $root, -1);
ok(scalar @ncpus_bad, 0, 'Bad argument to lgrp_cpus should return empty');
my $ncpus_bad = lgrp_cpus($c, $root, -1);
ok($ncpus_bad, undef, 'Bad argument to lgrp_cpus should return undef');
#
######################################################################

######################################################################
# The cookie should not be stale
#
ok(! lgrp_cookie_stale($c));
#
######################################################################

######################################################################
# Can we call lgrp_latency?
# The latencies from lgrp_latency and lgrp_latency_cookie should match.
##
my $latency = lgrp_latency($root, $root);
ok(defined $latency);

my $latency1 = lgrp_latency_cookie($c, $root, $root);
ok(defined $latency1);
ok($latency, $latency1, 'Latencies should match');
#
######################################################################
# Can we call lgrp_resources?
##
my @lgrps_c = lgrp_resources($c, $root, LGRP_RSRC_CPU);
my $nresources = lgrp_resources($c, $root, LGRP_RSRC_CPU);
ok(!defined $nresources) if $version < 2;
ok(scalar @lgrps_c, 0) if $version < 2;
ok($nresources) if $version >= 2;
ok(@lgrps_c) if $version >= 2;

##
# lgrp_fini should always succeed.
ok(lgrp_fini($c));


######################################################################
# Now test Object-Oriented interface.
##
$c = Sun::Solaris::Lgrp->new or
    die "Lgrp->new(LGRP_VIEW_OS): $!";

ok($c->view, LGRP_VIEW_OS);
ok($c->stale, 0, 'cookie is not stale');
ok($nlgrps, $c->nlgrps, 'nlgrps');
my @lg1 = $c->lgrps;
ok(@lgrps, @lg1);
my@leaves1 = $c->leaves;
ok(@leaves, @leaves1) or
    print STDERR "# \@leaves: @leaves, \@leaves1: @leaves\n";
ok($root, $c->root);
@cpus = lgrp_cpus($c->cookie, $root, LGRP_CONTENT_HIERARCHY);
my @cpus1 = $c->cpus($root, LGRP_CONTENT_HIERARCHY);
ok(@cpus, @cpus1) or
    print STDERR "# \@cpus: @cpus, \@cpus1: @cpus1\n";
ok(lgrp_latency($root, $root), $c->latency($root, $root));
my @lgrps_c1 = $c->resources($root, LGRP_RSRC_CPU);
ok(@lgrps_c, @lgrps_c1);
ok(lgrp_version(LGRP_VER_NONE), $c->version);

#
######################################################################
# Can we call lgrp_home?
##
$home = lgrp_home(P_PID, P_MYID);
ok(defined($home));
my $home1 = $c->home(P_PID, P_MYID);
ok($home1 == $home);
$home1 = lgrp_home(P_LWPID, 1);
ok($home1 == $home);
$home1 = $c->home(P_LWPID, 1);
ok($home1 == $home);

#
######################################################################
# Can we call lgrp_affinity_set?
##
my $affinity;

ok(LGRP_AFF_WEAK);
ok(P_LWPID);

$affinity = $c->affinity_set(P_PID, P_MYID, $home, LGRP_AFF_WEAK);
ok($affinity);

$affinity = $c->affinity_set(P_LWPID, 1, $home, LGRP_AFF_WEAK);
ok($affinity);

$affinity = lgrp_affinity_set(P_PID, P_MYID, $home, LGRP_AFF_WEAK);
ok($affinity);

$affinity = lgrp_affinity_set(P_LWPID, 1, $home, LGRP_AFF_WEAK);
ok($affinity);

#
######################################################################
# Can we call lgrp_affinity_get?
##
$affinity = lgrp_affinity_get(P_PID, P_MYID, $home);
ok($affinity = LGRP_AFF_WEAK);

$affinity = lgrp_affinity_get(P_LWPID, 1, $home);
ok($affinity == LGRP_AFF_WEAK);

$affinity = $c->affinity_get(P_PID, P_MYID, $home);
ok($affinity == LGRP_AFF_WEAK);

$affinity = $c->affinity_get(P_LWPID, 1, $home);
ok($affinity == LGRP_AFF_WEAK);

#
######################################################################
# THE END!
#########
