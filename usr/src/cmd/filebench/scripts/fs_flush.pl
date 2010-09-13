#!/usr/bin/perl
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

#
# Put commands in  here to flush the file system cache after
# file set creation but prior to steady state
#
# For most file systems, filebench already handles fs cache flushing
# For ZFS, it needs some help, so this script does
#    "zpool export <poolname>" then "zpool import <poolname>"
#

$fs = $ARGV[0];
$dir = $ARGV[1];

#
# if not zfs, inform user and exit.
#
if (($fs =~ m/^zfs$/) != 1) {
        print "filesystem type is: $fs, no action required, so exiting\n";
        exit(0);
}

#
# It is zfs. Find name of pool to export/import from supplied
# directory path name $dir
#
# Example:
# # zfs list -H
# tank    164K    24.0G   19K     /tank
# tank/a  18K     24.0G   18K     /tank/a
# tank/b  18K     24.0G   18K     /wombat
# # 
# # ./fs_flush zfs /wombat
# 'zpool export tank'
# 'zpool import tank'
# # 
#

# Get a list of zfs file systems mounted locally
@zlist = `/usr/sbin/zfs list -H`;

#
# Compare the list with the supplied directory path name
#
chomp @zlist;
foreach ( @zlist ) {
	#
	# For listed zfs file systems, extract the root and
	# mount point information
	#
        my $zline = $_;
        ($root, $b, $c, $d, $mntpnt) = split /\t/, $zline, 5;

	# See if the supplied directory path includes this mount point
        if(($mntpnt ne "\/") && ($dir =~/^$mntpnt/)) {

		#
		# We have a winner! The root name up to the
		# first forward slash is the pool name
		#
                ($pool) = split /\//, $root;

		# save zpool.cache
		my $tempfile = "/tmp/zpool.cache$$";
		my $cachefile = "";

		if (run_prog("cp /etc/zfs/zpool.cache $tempfile") == 0) {
			$cachefile = "-c $tempfile "
		}

		# Do the cache flushing
		
                print "'zpool export \/ import $pool'\n";
		if (run_prog("zpool export $pool") == 0) {
			system("zpool import $cachefile$pool");
		}
		system("rm -f $tempfile")	if ($cachefile ne "");
                exit(0);
        }
}
exit(-1);

sub run_prog
{
	my $progname = shift;

	my $res = system($progname);

	#return error if failed for any reason
	return -1 if (($res == -1) || ($res & 127));

	return ($res >> 8);
}
