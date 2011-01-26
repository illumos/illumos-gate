#!/usr/perl5/5.8.4/bin/perl -w
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
# Copyright (c) 2011 Joyent, Inc.
#
# vfsstat - report VFS statistics per zone
#
# USAGE:    vfsstat [-hM] [interval [count]]
#           -h              # help
#	    -M              # print results in MB/s
#
#   eg,	    vfsstat               # print summary since zone boot
#           vfsstat 1             # print continually every 1 second
#           vfsstat 1 5           # print 5 times, every 1 second
#           vfsstat -M 1          # print results in MB/s, every 1 second
#
# NOTES:
#
# - The calculations and output fields emulate those from iostat(1M) as closely
#   as possible.  When only one zone is actively performing disk I/O, the
#   results from iostat(1M) in the global zone and vfsstat in the local zone
#   should be almost identical.
#
# - As with iostat(1M), a result of 100% for disk utilization does not mean that
#   the disk is fully saturated.  Instead, that measurement just shows that at
#   least one operation was pending over the last quanta of time examined.
#   Since disk devices can process more than one operation concurrently, this
#   measurement will frequently be 100% but the disk can still offer higher
#   performance.
#
# - This script is based on Brendan Gregg's K9Toolkit examples:
#
#	http://www.brendangregg.com/k9toolkit.html
#

use Getopt::Std;
use Sun::Solaris::Kstat;
my $Kstat = Sun::Solaris::Kstat->new();

# Process command line args
usage() if defined $ARGV[0] and $ARGV[0] eq "--help";
getopts('hM') or usage();
usage() if defined $main::opt_h;
my $USE_MB  = defined $main::opt_M ? $main::opt_M : 0;

my ($interval, $count);
if ( defined($ARGV[0]) ) {
	$interval = $ARGV[0];
	$count = defined ($ARGV[1]) ? $ARGV[1] : 2**32;
	usage() if ($interval == 0);
} else {
	$interval = 1;
	$count = 1; 
}

$main::opt_h = 0;

my $module = 'zones';
chomp(my $zname = (`/sbin/zonename`));

my $NS_PER_SEC = 1000 * 1000 * 1000;
my $BYTES_PER_MB = 1024 * 1024;
my $BYTES_PER_KB = 1024;

my $BYTES_PREFIX = $USE_MB ? "M" : "k";
my $BYTES_DIVISOR = $USE_MB ? $BYTES_PER_MB : $BYTES_PER_KB;

my $Modules = $Kstat->{$module};

my $old_r_ops = 0;
my $old_w_ops = 0;
my $old_r_bytes = 0;
my $old_w_bytes = 0;
my $old_r_time = 0;
my $old_w_time = 0;
my $old_r_etime = 0;
my $old_w_etime = 0;
my $old_r_lentime = 0;
my $old_w_lentime = 0;

my $ii = 0;
$Kstat->update();

while (1) {
	foreach my $instance (sort keys(%$Modules)) {
		my $Instances = $Modules->{$instance};
	
		foreach my $name (keys(%$Instances)) {
			$Stats = $Instances->{$name};

			if ($name eq 'zone_vfs' &&
			    $Stats->{'zonename'} eq $zname) {
				print_stats();
			}
		}
	}
	
	$ii++;
	if ($ii == $count) {
		exit (0);
	}

	sleep ($interval);
	$Kstat->update();
}

sub print_stats {
	my $r_ops = $Stats->{'nread'};
	my $w_ops = $Stats->{'nwrite'};
	my $r_bytes = $Stats->{'read_bytes'};
	my $w_bytes = $Stats->{'write_bytes'};

	my $r_time = $Stats->{'read_time'};
	my $w_time = $Stats->{'write_time'};
	my $r_lentime = $Stats->{'read_lentime'};
	my $w_lentime = $Stats->{'write_lentime'};

	my $r_etime = ($Stats->{'read_lastupdate'} - $old_r_etime) /
	    $NS_PER_SEC;
	my $w_etime = ($Stats->{'write_lastupdate'} - $old_w_etime) /
	    $NS_PER_SEC;

	# An elapsed time of zero is not a good idea
	if ($r_etime == 0) {
		$r_etime = $interval;
	}
	if ($w_etime == 0) {
		$w_etime = $interval;
	}

	my $r_tps = ($r_ops - $old_r_ops) / $r_etime;
	my $w_tps = ($w_ops - $old_w_ops) / $w_etime;

	# XXX Need to investigate how to calculate this
	my $wait_t = 0.0;
	
	# Calculate average length of active queue
	my $r_actv = ($r_lentime - $old_r_lentime) / $r_etime / $NS_PER_SEC;
	my $w_actv = ($w_lentime - $old_w_lentime) / $w_etime / $NS_PER_SEC;

	# Calculate average service time
	my $read_t = $r_tps > 0 ? $r_actv * (1000 / $r_tps) : 0.0;
	my $writ_t = $w_tps > 0 ? $w_actv * (1000 / $w_tps) : 0.0;

	# Calculate the % time the VFS layer is active
	my $r_b_pct = ($r_time - $old_r_time) / ($r_etime * $NS_PER_SEC * 100);
	my $w_b_pct = ($w_time - $old_w_time) / ($w_etime * $NS_PER_SEC * 100);
	my $b_pct = ($r_b_pct + $w_b_pct) / 2;

	printf("   r/s    w/s   %sr/s   %sw/s wait_t ractv wactv " .
	    "read_t writ_t  %%b zone\n", $BYTES_PREFIX, $BYTES_PREFIX);
	printf("%6.1f %6.1f %6.1f %6.1f %6.1f %5.1f %5.1f %6.1f %6.1f " .
	    "%3d %s\n",
	    ($r_ops - $old_r_ops) / $r_etime,
	    ($w_ops - $old_w_ops) / $w_etime,
	    ($r_bytes - $old_r_bytes) / $r_etime / $BYTES_DIVISOR,
	    ($w_bytes - $old_w_bytes) / $w_etime / $BYTES_DIVISOR,
	    $wait_t,
	    $r_actv,
	    $w_actv,
	    $read_t,
	    $writ_t,
	    $b_pct,
	    $zname);

	# Save current calculations for next loop
	$old_r_ops = $r_ops;
	$old_w_ops = $w_ops;
	$old_r_bytes = $r_bytes;
	$old_w_bytes = $w_bytes;
	$old_r_time = $r_time;
	$old_w_time = $w_time;
	$old_r_etime = $Stats->{'read_lastupdate'};
	$old_w_etime = $Stats->{'write_lastupdate'};
	$old_r_lentime = $r_lentime;
	$old_w_lentime = $w_lentime;
}

sub usage {
        print STDERR <<END;
USAGE: vfsstat [-hM] [interval [count]]
   eg, vfsstat               # print summary since zone boot
       vfsstat 1             # print continually every 1 second
       vfsstat 1 5           # print 5 times, every 1 second
       vfsstat -M            # print results in MB/s
END
        exit 1;
}
