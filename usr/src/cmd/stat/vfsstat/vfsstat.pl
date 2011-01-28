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

my $BYTES_PER_MB = 1024 * 1024;
my $BYTES_PER_KB = 1024;

my $BYTES_PREFIX = $USE_MB ? "M" : "k";
my $BYTES_DIVISOR = $USE_MB ? $BYTES_PER_MB : $BYTES_PER_KB;

my $Modules = $Kstat->{'zone_vfs'};

my $old_rops = 0;
my $old_wops = 0;
my $old_rbytes = 0;
my $old_wbytes = 0;
my $old_rtime = 0;
my $old_wtime = 0;
my $old_rlentime = 0;
my $old_wlentime = 0;
my $old_snaptime = 0;

my $ii = 0;
$Kstat->update();

while (1) {
	printf("   r/s    w/s   %sr/s   %sw/s wait_t ractv wactv " .
	    "read_t writ_t  %%b zone\n", $BYTES_PREFIX, $BYTES_PREFIX);

	foreach my $instance (sort keys(%$Modules)) {
		my $Instances = $Modules->{$instance};
	
		foreach my $name (keys(%$Instances)) {
			$Stats = $Instances->{$name};
			print_stats($name);
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
	my $zonename = $_[0];

	my $rops = $Stats->{'reads'};
	my $wops = $Stats->{'writes'};
	my $rbytes = $Stats->{'nread'};
	my $wbytes = $Stats->{'nwritten'};

	my $rtime = $Stats->{'rtime'};
	my $wtime = $Stats->{'wtime'};
	my $rlentime = $Stats->{'rlentime'};
	my $wlentime = $Stats->{'wlentime'};

	my $etime = $Stats->{'snaptime'} -
	    ($old_snaptime > 0 ? $old_snaptime : $Stats->{'crtime'});

	my $r_tps = ($rops - $old_rops) / $etime;
	my $w_tps = ($wops - $old_wops) / $etime;

	# XXX Need to investigate how to calculate this
	my $wait_t = 0.0;
	
	# Calculate average length of active queue
	my $r_actv = ($rlentime - $old_rlentime) / $etime;
	my $w_actv = ($wlentime - $old_wlentime) / $etime;

	# Calculate average service time
	my $read_t = $r_tps > 0 ? $r_actv * (1000 / $r_tps) : 0.0;
	my $writ_t = $w_tps > 0 ? $w_actv * (1000 / $w_tps) : 0.0;

	# Calculate the % time the VFS layer is active
	my $r_b_pct = (($rtime - $old_rtime) / $etime) * 100;
	my $w_b_pct = (($wtime - $old_wtime) / $etime) * 100;
	my $b_pct = ($r_b_pct + $w_b_pct) / 2;

	printf("%6.1f %6.1f %6.1f %6.1f %6.1f %5.1f %5.1f %6.1f %6.1f " .
	    "%3d %s\n",
	    ($rops - $old_rops) / $etime,
	    ($wops - $old_wops) / $etime,
	    ($rbytes - $old_rbytes) / $etime / $BYTES_DIVISOR,
	    ($wbytes - $old_wbytes) / $etime / $BYTES_DIVISOR,
	    $wait_t,
	    $r_actv,
	    $w_actv,
	    $read_t,
	    $writ_t,
	    $b_pct,
	    $zonename);

	# Save current calculations for next loop
	$old_rops = $rops;
	$old_wops = $wops;
	$old_rbytes = $rbytes;
	$old_wbytes = $wbytes;
	$old_rtime = $rtime;
	$old_wtime = $wtime;
	$old_rlentime = $rlentime;
	$old_wlentime = $wlentime;
	$old_snaptime = $Stats->{'snaptime'};
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
