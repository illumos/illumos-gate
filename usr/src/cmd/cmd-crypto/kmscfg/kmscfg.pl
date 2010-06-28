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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#
# This program initializes the private data needed to initialize
# the PKCS#11 KMS provider (/usr/lib/security/pkcs11_kms.so.1) in
# the Solaris Cryptographic Framework.
#
# It takes the following options:
#	[-p Profile Name]	
#	[-a Agent ID]
#	[-i Agent Address]
#	[-t Transaction Timeout]
#	[-f Failover Limit]
#	[-d Discovery Frequency]
#	[-?]
#

use strict;
use warnings;
use locale;
use Getopt::Std;
use POSIX qw(locale_h);
use File::Basename;
use Sun::Solaris::Utils qw(textdomain gettext gmatch);

my $cmd = basename($0);

sub fatal {
	print STDERR @_;
	exit(1);
}

sub usage {
	print STDERR gettext("Usage:") . " $cmd\n" .
  	gettext(
	"\t[-p[rofile] Profile Name]	The name of the KMA profile to use.\n" .
	"\t[-a[gent] Agent ID]		The KMA agent ID.\n" .
	"\t[-i[paddr] Agent Address]	Address of the KMA\n" .
	"\t[-t[imeout] Transaction Timeout] Transaction timeout period (integer)\n" .
	"\t[-f[ailover] Failover Limit]	Maximum failover limit (integer)\n" .
	"\t[-d[iscovery] Discovery Freq]    Frequency to attempt KMA discovery\n");
	exit(1);
}

sub get_input {
	my($prompt, $default) = @_;
	my $resp;
	if (length($default)) {
		print "$prompt [$default]: ";
	} else {
		print "$prompt: ";
	}
	chop ($resp = <STDIN>);
	if (length($default)) {
		return $resp ? $resp : $default;
	}
	return $resp;
}

setlocale(LC_ALL, "");
textdomain(TEXT_DOMAIN);

my($profile, $agentid, $address, $timeout, $failover, $discovery, $help);

my (%opt);
getopts('?p:a:i:t:f:d:', \%opt) || usage();
usage() if exists ($opt{'?'});

my $TOKENDIR;

if (exists($ENV{KMSTOKEN_DIR})) {
	$TOKENDIR= $ENV{KMSTOKEN_DIR};
} else {
	my $name = getpwuid($<);
	$TOKENDIR= "/var/kms/$name";
}

my $cfgfile = "$TOKENDIR/kmstoken.cfg";

if ( ! -d $TOKENDIR ) {
	mkdir ($TOKENDIR, 0700) || die "mkdir $TOKENDIR error: $!\n";
}

if (-f $cfgfile) {
	my $ans;
	print gettext("KMS Token config file ") . "($cfgfile) " .
		gettext("already exists,\n" .
		"do you want to overwrite it (Y/n)? ");
	chop ($ans = <STDIN>);
	if (length($ans)) {
		if ($ans !~ /^[yY].*/) {
			exit(0);
		}
	}
}

if (!exists($opt{'p'})) {
	$profile = get_input("Profile Name", "");
	if (!length($profile)) {
		fatal(gettext("You must enter a KMA Profile Name.\n"));
	}
} else {
	$profile = $opt{'p'};
}

if (!exists($opt{'a'})) {
	$agentid = get_input("Agent ID", "");
	if (!length($agentid)) {
		fatal(gettext("You must enter a KMA Profile ID.\n"));
	}
} else {
	$agentid = $opt{'a'};
}

if (!exists($opt{'i'})) {
	$address = get_input("KMA IP Address", "");
	if (!length($address)) {
		fatal(gettext("You must enter a KMA IP Address.\n"));
	}
} else {
	$address = $opt{'i'};
}

if (!exists($opt{'t'})) {
	$timeout = 10;
} else {
	$timeout = $opt{'t'};
}

if (!exists($opt{'f'})) {
	$failover = 3;
} else {
	$failover = $opt{'f'};
}

if (!exists($opt{'d'})) {
	$discovery = 10;
} else {
	$discovery = $opt{'d'};
}

# Save the old one
if (-f $cfgfile) {
	rename($cfgfile, "$cfgfile.old");
}

my $FH;

open($FH, ">$cfgfile");
print $FH "#\n# Profile Name\n#\n$profile\n";
print $FH "#\n# Agent ID\n#\n$agentid\n";
print $FH "#\n# KMA Address\n#\n$address\n";
print $FH "#\n# Transaction Timeout\n#\n$timeout\n";
print $FH "#\n# Failover Limit\n#\n$failover\n";
print $FH "#\n# Discovery Frequency\n#\n$discovery\n";
print $FH "#\n# Security Mode\n#\n1\n";
close ($FH);

exit(0);
