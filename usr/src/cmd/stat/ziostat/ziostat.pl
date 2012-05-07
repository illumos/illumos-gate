#!/usr/perl5/bin/perl -w
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
# USAGE:    ziostat [-hIMrzZ] [interval [count]]
#           -h              # help
#           -I              # print results per interval (where applicable)
#	    -M              # print results in MB/s
#	    -r		    # print data in comma-separated format
#	    -z		    # hide zones with no ZFS I/O activity
#	    -Z		    # print data for all zones
#
#   eg,	    ziostat               # print summary since zone boot
#           ziostat 1             # print continually every 1 second
#           ziostat 1 5           # print 5 times, every 1 second
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
getopts('hIMrzZ') or usage();
usage() if defined $main::opt_h;
$main::opt_h = 0;

my $USE_MB = defined $main::opt_M ? $main::opt_M : 0;
my $USE_INTERVAL = defined $main::opt_I ? $main::opt_I : 0;
my $USE_COMMA = defined $main::opt_r ? $main::opt_r : 0;
my $HIDE_ZEROES = defined $main::opt_z ? $main::opt_z : 0;
my $ALL_ZONES = defined $main::opt_Z ? $main::opt_Z : 0;

my ($interval, $count);
if ( defined($ARGV[0]) ) {
	$interval = $ARGV[0];
	$count = defined ($ARGV[1]) ? $ARGV[1] : 2**32;
	usage() if ($interval == 0);
} else {
	$interval = 1;
	$count = 1; 
}

my $HEADER_FMT = $USE_COMMA ?
     "r/%s,%sr/%s,actv,wsvc_t,asvc_t,%%b,zone\n" :
     "    r/%s   %sr/%s   actv wsvc_t asvc_t  %%b zone\n";
my $DATA_FMT = $USE_COMMA ?
    "%.1f,%.1f,%.1f,%.1f,%.1f,%d,%s,%d\n" :
    " %6.1f %6.1f %6.1f %6.1f %6.1f %3d %s (%d)\n";

my $BYTES_PREFIX = $USE_MB ? "M" : "k";
my $BYTES_DIVISOR = $USE_MB ? 1024 * 1024 : 1024;
my $INTERVAL_SUFFIX = $USE_INTERVAL ? "i" : "s";
my $NANOSEC = 1000000000;

my @fields = ( 'reads', 'nread', 'waittime', 'rtime', 'rlentime', 'snaptime' );

chomp(my $curzone = (`/sbin/zonename`));

# Read list of visible zones and their zone IDs
my @zones = ();
my %zoneids = ();
my $zoneadm = `zoneadm list -p | cut -d: -f1,2`;
@lines = split(/\n/, $zoneadm);
foreach $line (@lines) {
	@tok = split(/:/, $line);
	$zoneids->{$tok[1]} = $tok[0];
	push(@zones, $tok[1]);
}

my %old = ();
my $rows_printed = 0;

$Kstat->update();

for (my $ii = 0; $ii < $count; $ii++) {
	# Print the column header every 20 rows
	if ($rows_printed == 0 || $ALL_ZONES) {
		printf($HEADER_FMT, $INTERVAL_SUFFIX, $BYTES_PREFIX,
		    $INTERVAL_SUFFIX, $INTERVAL_SUFFIX);
	}

	$rows_printed = $rows_printed >= 20 ? 0 : $rows_printed + 1;

	foreach $zone (@zones) {
		if ((!$ALL_ZONES) && ($zone ne $curzone)) {
			next;
		}

		if (! defined $old->{$zone}) {
			$old->{$zone} = ();
			foreach $field (@fields) { $old->{$zone}->{$field} = 0; }
		}

		#
		# Kstats have a 30-character limit (KSTAT_STRLEN) on their
		# names, so if the zone name exceeds that limit, use the first
		# 30 characters.
		#
		my $trimmed_zone = substr($zone, 0, 30);
		my $zoneid = $zoneids->{$zone};

		print_stats($zone, $zoneid,
		    $Kstat->{'zone_zfs'}{$zoneid}{$trimmed_zone}, $old->{$zone});
	}

	sleep ($interval);
	$Kstat->update();
}

sub print_stats {
	my $zone = $_[0];
	my $zoneid = $_[1];
	my $data = $_[2];
	my $old = $_[3];

	my $etime = $data->{'snaptime'} -
	    ($old->{'snaptime'} > 0 ? $old->{'snaptime'} : $data->{'crtime'});

	# Calculate basic statistics
	my $rate_divisor = $USE_INTERVAL ? 1 : $etime;
	my $reads = ($data->{'reads'} - $old->{'reads'}) / $rate_divisor;
	my $nread = ($data->{'nread'} - $old->{'nread'}) /
	    $rate_divisor / $BYTES_DIVISOR;

	# Calculate overall transactions per second
	my $ops = $data->{'reads'} - $old->{'reads'};
	my $tps = $ops / $etime;

	# Calculate average length of disk run queue
	my $actv = (($data->{'rlentime'} - $old->{'rlentime'}) / $NANOSEC) /
	    $etime;

	# Calculate average disk wait and service times
	my $wsvc = $ops > 0 ? (($data->{'waittime'} - $old->{'waittime'}) /
	    1000000) / $ops : 0.0;
	my $asvc = $tps > 0 ? $actv * (1000 / $tps) : 0.0;

	# Calculate the % time the disk run queue is active
	my $b_pct = ((($data->{'rtime'} - $old->{'rtime'}) / $NANOSEC) /
	    $etime) * 100;

	if (! $HIDE_ZEROES || $reads != 0.0 || $nread != 0.0 ) {
		printf($DATA_FMT, $reads, $nread, $actv, $wsvc, $asvc,
		    $b_pct, substr($zone, 0, 8), $zoneid);
	}

	# Save current calculations for next loop
	foreach (@fields) { $old->{$_} = $data->{$_}; }
}

sub usage {
        print STDERR <<END;
USAGE: ziostat [-hIMrzZ] [interval [count]]
   eg, ziostat               # print summary since zone boot
       ziostat 1             # print continually every 1 second
       ziostat 1 5           # print 5 times, every 1 second
       ziostat -I            # print results per interval (where applicable)
       ziostat -M            # print results in MB/s
       ziostat -r            # print results in comma-separated format
       ziostat -z            # hide zones with no ZFS I/O activity
       ziostat -Z            # print results for all zones
END
        exit 1;
}
