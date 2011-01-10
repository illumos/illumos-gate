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
# ziostat - report I/O statistics per zone
#
# USAGE:    ziostat [-hM] [interval [count]]
#           -h              # help
#	    -M              # print results in MB/s
#
#   eg,	    ziostat               # print summary since zone boot
#           ziostat 1             # print continually every 1 second
#           ziostat 1 5           # print 5 times, every 1 second
#           ziostat -M 1          # print results in MB/s, every 1 second
#
# NOTES:
#
# - The calculations and output fields emulate those from iostat(1M) as closely
#   as possible.  When only one zone is actively performing disk I/O, the
#   results from iostat(1M) in the global zone and ziostat in the local zone
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

my $Modules = $Kstat->{$module};

my $old_svc_lentime = 0;
my $old_svc_time = 0;
my $old_rops = 0;
my $old_wops = 0;
my $old_rbytes = 0;
my $old_wbytes = 0;
my $old_hrtime = 0;

my $ii = 0;
while (1) {
	$Kstat->update();

	foreach my $instance (sort keys(%$Modules)) {
		my $Instances = $Modules->{$instance};
	
		foreach my $name (keys(%$Instances)) {
			$Stats = $Instances->{$name};

			if ($Stats->{'zonename'} eq $zname) {
				print_stats();
			}
		}
	}
	
	$ii++;
	if ($ii == $count) {
		exit (0);
	}

	sleep ($interval);
}

sub print_stats {
	my $NS_PER_SEC = 1000 * 1000 * 1000;
	my $BYTES_PER_MB = 1024 * 1024;
	my $BYTES_PER_KB = 1024;

	my $svc_lentime = $Stats->{'io_svc_lentime'};
	my $svc_time = $Stats->{'io_svc_time'};
	my $rops = $Stats->{'io_physical_read_ops'};
	my $wops = $Stats->{'io_physical_write_ops'};
	my $rbytes = $Stats->{'io_physical_read_bytes'};
	my $wbytes = $Stats->{'io_physical_write_bytes'};

	my $etime = ($Stats->{'io_svc_lastupdate'} - $old_hrtime) / $NS_PER_SEC;

	# An elapsed time of zero is not a good idea
	if ($etime == 0) {
		$etime = 0.1;
	}

	# Calculate read, write, and overall transactions per second
	my $rps = ($rops - $old_rops) / $etime;
	my $wps = ($wops - $old_wops) / $etime;
	my $tps = $rps + $wps;
	
	# Calculate average length of active queue
	my $actv = ($svc_lentime - $old_svc_lentime) / $etime / $NS_PER_SEC;

	# Calculate average service time
	my $asvc = $tps > 0 ? $actv * (1000 / $tps) : 0.0;

	# Calculate the % time the disk is active
	my $b_pct = ($svc_time - $old_svc_time) / ($etime * $NS_PER_SEC * 100);

	my $bytes_divisor = $USE_MB ? $BYTES_PER_MB : $BYTES_PER_KB;

	printf("    r/s    w/s   %sr/s   %sw/s   actv  asvc_t    %%b   zone\n",
	    $USE_MB ? "M" : "k", $USE_MB ? "M" : "k");
	printf("%7.1f %6.1f %6.1f %6.1f %6.1f %7.1f   %3d   %s\n",
	    ($rops - $old_rops) / $etime,
	    ($wops - $old_wops) / $etime,
	    ($rbytes - $old_rbytes) / $etime / $bytes_divisor,
	    ($wbytes - $old_wbytes) / $etime / $bytes_divisor,
	    $actv,
	    $asvc,
	    $b_pct,
	    $zname);

	# Save current calculations for next loop
	$old_svc_lentime = $svc_lentime;
	$old_svc_time = $svc_time;
	$old_rops = $rops;
	$old_wops = $wops;
	$old_rbytes = $rbytes;
	$old_wbytes = $wbytes;
	$old_hrtime = $Stats->{'io_svc_lastupdate'};
}

sub usage {
        print STDERR <<END;
USAGE: ziostat [-hM] [interval [count]]
   eg, ziostat               # print summary since zone boot
       ziostat 1             # print continually every 1 second
       ziostat 1 5           # print 5 times, every 1 second
       ziostat -M            # print results in MB/s
END
        exit 1;
}
