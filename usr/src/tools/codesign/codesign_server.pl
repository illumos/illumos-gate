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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# Server program for code signing server
#
# This program implements an ssh-based service to add digital
# signatures to files. The sshd_config file on the server
# contains an entry like the following to invoke this program:
#
#	Subsystem codesign /opt/signing/bin/server
#
# The client program sends a ZIP archive of the file to be
# signed along with the name of a signing credential stored
# on the server. Each credential is a directory containing
# a public-key certificate, private key, and a script to
# perform the appropriate signing operation.
#
# This program unpacks the input ZIP archive, invokes the
# signing script for the specified credential, and sends
# back an output ZIP archive, which typically contains the
# (modified) input file but may also contain additional
# files created by the signing script.

use strict;
use File::Temp 'tempdir';
use File::Path;

my $Base = "/opt/signing";
my $Tmpdir = tempdir(CLEANUP => 1);	# Temporary directory
my $Session = $$;

#
# Main program
#

# Set up
open(AUDIT, ">>$Base/audit/log");
$| = 1;	# Flush output on every write

# Record user and client system
my $user = `/usr/ucb/whoami`;
chomp($user);
my ($client) = split(/\s/, $ENV{SSH_CLIENT});
audit("START User=$user Client=$client");

# Process signing requests
while (<STDIN>) {
	if (/^SIGN (\d+) (\S+) (\S+)/) {
		sign($1, $2, $3);
	} else {
		abnormal("WARNING Unknown command");
	}
}
exit(0);

#
# get_credential(name)
#
# Verify that the user is allowed to use the named credential and
# return the path to the credential directory. If the user is not
# authorized to use the credential, return undef.
#
sub get_credential {
	my $name = shift;
	my $dir;

	$dir = "$Base/cred/$2";
	if (!open(F, "<$dir/private")) {
		abnormal("WARNING Credential $name not available");
		$dir = undef;
	}
	close(F);
	return $dir;
}

#
# sign(size, cred, path)
#
# Sign an individual file.
#
sub sign {
	my ($size, $cred, $path) = @_;
	my ($cred_dir, $msg);

	# Read input file
	recvfile("$Tmpdir/in.zip", $size) || return;

	# Check path for use of .. or absolute pathname
	my @comp = split(m:/:, $path);
	foreach my $elem (@comp) {
		if ($elem eq "" || $elem eq "..") {
			abnormal("WARNING Invalid path $path");
			return;
		}
	}

	# Get credential directory
	$cred_dir = get_credential($cred) || return;

	# Create work area
	rmtree("$Tmpdir/reloc");
	mkdir("$Tmpdir/reloc");
	chdir("$Tmpdir/reloc");

	# Read and unpack input ZIP archive
	system("/usr/bin/unzip -qo ../in.zip $path");

	# Sign input file using credential-specific script
	$msg = `cd $cred_dir; ./sign $Tmpdir/reloc/$path`;
	if ($? != 0) {
		chomp($msg);
		abnormal("WARNING $msg");
		return;
	}

	# Pack output file(s) in ZIP archive and return
	unlink("../out.zip");
	system("/usr/bin/zip -qr ../out.zip .");
	chdir($Tmpdir);
	my $hash = `digest -a md5 $Tmpdir/reloc/$path`;
	sendfile("$Tmpdir/out.zip", $path) || return;

	# Audit successful signing
	chomp($hash);
	audit("SIGN $path $cred $hash");
}

#
# sendfile(file, path)
#
# Send a ZIP archive to the client. This involves sending
# an OK SIGN response that includes the file size, followed by
# the contents of the archive itself.
#
sub sendfile {
	my ($file, $path) = @_;
	my ($size, $bytes);

	$size = -s $file;
	if (!open(F, "<$file")) {
		abnormal("ERROR Internal read error");
		return (0);
	}
	read(F, $bytes, $size);
	close(F);
	print "OK SIGN $size $path\n";
	syswrite(STDOUT, $bytes, $size);
	return (1);
}

#
# recvfile(file, size)
#
# Receive a ZIP archive from the client. The caller
# provides the size argument previously obtained from the 
# client request.
#
sub recvfile {
	my ($file, $size) = @_;
	my $bytes;
	
	if (!read(STDIN, $bytes, $size)) {
		abnormal("ERROR No input data");
		return (0);
	}
	if (!open(F, ">$file")) {
		abnormal("ERROR Internal write error");
		return (0);
	}
	syswrite(F, $bytes, $size);
	close(F);
	return (1);
}

#
# audit(msg)
#
# Create an audit record. All records have this format:
#	[date] [time] [session] [keyword] [other parameters]
# The keywords START and END mark the boundaries of a session.
#
sub audit {
	my ($msg) = @_;
	my ($sec, $min, $hr, $day, $mon, $yr) = localtime(time);
	my $timestamp = sprintf("%04d-%02d-%02d %02d:%02d:%02d",
		$yr+1900, $mon+1, $day, $hr, $min, $sec);

	print AUDIT "$timestamp $Session $msg\n";
}

#
# abnormal(msg)
#
# Respond to an abnormal condition, which may be fatal (ERROR) or
# non-fatal (WARNING). Send the message to the audit error log
# and to the client program. Exit in case of fatal errors.
#
sub abnormal {
	my $msg = shift;

	audit($msg);
	print("$msg\n");
	exit(1) if ($msg =~ /^ERROR/);
}

#
# END()
#
# Clean up prior to normal or abnormal exit.
#
sub END {
	audit("END");
	close(AUDIT);
	chdir("");	# so $Tmpdir can be removed
}
