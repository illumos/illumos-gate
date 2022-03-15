#!/usr/bin/perl -w
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

#
# RCM script to allow/deny removal of miscellaneous virtual devices
# from an LDoms domain.
#
# Currently, the only device in this category is vcc
# (virtual-console-concentrator).
#

use strict;

my $vcc_path_prefix = "/devices/virtual-devices\@100/channel-devices\@200/";
my $vcc_leaf_node = "virtual-console-concentrator";

my $cmd;
my %dispatch;


sub do_scriptinfo
{
	print "rcm_log_debug=do_scriptinfo\n";

	print "rcm_script_version=1\n";
	print "rcm_script_func_info=VIO DR (VCC)\n";

	exit (0);
}

sub do_resourceinfo
{
	print "rcm_log_debug=do_resourceinfo\n";
	print "rcm_resource_usage_info=" .
		"in use by virtual console service (vntsd)\n";

	exit (0);
}

sub do_register
{
	print "rcm_log_debug=do_register\n";

	#
	# Identify any vcc devices in the system.  Vntsd always keeps the
	# ":ctl" node open as a way to create or remove console ports, so
	# use that as a proxy for the entire device.
	#
	my $path = $vcc_path_prefix . $vcc_leaf_node . "\*ctl";
	my @devs = glob $path;
	my $consdev;

	#
	# Tell the RCM framework to notify us if there is a request to
	# remove a vcc device.
	#
	printf "rcm_log_debug=do_register: %d devices\n", scalar(@devs);
	foreach $consdev(@devs) {
		print "rcm_resource_name=$consdev\n";
	}

	exit (0);
}

sub do_queryremove
{
	my $rsrc = shift(@ARGV);

	print "rcm_log_debug=do_queryremove: '$rsrc'\n";

	#
	# fuser(8) sends to stdout the pids of any processes using the
	# device.  Some other information always appears on stderr and
	# must be discarded to avoid invalidating the test.
	#
	my $str = `/usr/sbin/fuser $rsrc 2>/dev/null`;
	
	if ($? != 0) {
		printf "rcm_log_err=do_queryremove: " .
		    "fuser failed (status %d)\n", $?;
		print "rcm_failure_reason=helper command (fuser) failed\n";
		exit (1);
	}

	my @words = split(/ /, $str);

	# Allow the operation if device not opened by any processes.
	if (scalar(@words) != 0) {
		print "rcm_log_debug=BLOCKED\n";
		print "rcm_failure_reason=device " .
		    "in use by virtual console service (vntsd)\n";
		exit (3);
	}

	exit (0);
}

$cmd = shift(@ARGV);

# dispatch table for RCM commands
%dispatch = (
	"scriptinfo"	=>	\&do_scriptinfo,
	"resourceinfo"	=>	\&do_resourceinfo,
	"register"	=>	\&do_register,
	"queryremove"	=>	\&do_queryremove
);

if (defined($dispatch{$cmd})) {
	&{$dispatch{$cmd}};
} else {
	exit (2);
}
