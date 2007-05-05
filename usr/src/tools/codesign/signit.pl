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

# signit [-q] [-i dir][-o dir] [-l user]
#
# Client program for use with code signing server.
# Reads a list of signing credential names and file pathnames
# from standard input. Each file is read from the input directory,
# sent to the signing server, signed with the specified credential, 
# and written to the output directory.
#
# Options:
#	-q	quiet operation: avoid printing files successfully signed
#	-i dir	input directory (defaults to current dir)
#	-o dir	output directory (defautls to input dir)
#	-l user	user account on signing server (defaults to current user)
#
# The CODESIGN_SERVER environment variable can be used to
# specify the hostname or IP address of the signing server
# (defaults to quill.sfbay).

use strict;
use Cwd;
use File::Temp 'tempdir';
use Getopt::Std;
use IPC::Open2;

#
# Global variables
#
my ($Indir, $Outdir);	# Input and output directories (may be the same)
my $Server;		# Signing server hostname
my $Quiet;		# Suppress printing each file successfully signed
my ($pid);		# Process id for ssh client
my @cred_rules;		# Array of path prefixes and credentials to use
my $Tmpdir = tempdir(CLEANUP => 1);	# Temporary directory
my $Warnings = 0;	# Count of warnings returned


#
# Main program
#

$Server = $ENV{CODESIGN_SERVER} || "quill.sfbay";

# Get command-line arguments
our($opt_c, $opt_i, $opt_o, $opt_l, $opt_q);
if (!getopts("i:o:c:l:q")) {
	die "Usage: $0 [-i dir] [-o dir] [-l user]\n";
}
$Quiet = $opt_q;

# Get input/output directories
$Indir = $opt_i || getcwd();	# default to current dir
$Outdir = $opt_o || $Indir;	# default to input dir
$Indir = getcwd() . "/$Indir" if (substr($Indir, 0, 1) ne "/");
$Outdir = getcwd() . "/$Outdir" if (substr($Outdir, 0, 1) ne "/");

# Ignore SIGPIPE to allow proper error messages
$SIG{PIPE} = 'IGNORE';

# Create ssh connection to server
my(@args);
if (defined($opt_l)) {
	push @args, "-l", $opt_l;
}
push @args, "-s", $Server, "codesign";
$pid = open2(*SRV_OUT, *SRV_IN, "/usr/bin/ssh", @args) or 
	die "ERROR Connection to server $Server failed\n";
select(SRV_IN); $| = 1; select(STDOUT);	# unbuffered writes

# Sign each file with the specified credential
chdir($Indir);
while (<>) {
	my ($cred, $path) = split;

	sign_file($cred, $path);
}
exit($Warnings > 0);

#
# END()
#
# Clean up after normal or abnormal exit.
#
sub END {
	my $old_status = $?;

	$? = 0;
	close(SRV_IN);
	close(SRV_OUT);
	waitpid($pid, 0) if ($pid);
	if ($?) {
		print STDERR "ERROR Connection to server $Server failed\n";
		$? = 1;
	}
	$? = $old_status if ($? == 0);
}

#
# debug(msg)
#
# Print debug message to standard error.
#
sub debug {
	print STDERR "### @_";
}

#
# check_response(str)
#
# Validate response from server. Print messages for warnings or errors,
# and exit in the case of an error. If the response indicates a successful
# signing operation, return the size of the output data.
#
sub check_response {
	my ($str) = @_;

	if ($str =~ /^OK SIGN (\d+)/) {
		return ($1);
	}
	elsif ($str =~ /^OK/) {
		return (0);
	}
	elsif ($str =~ /^WARNING/) {
		print STDERR $str;
		$Warnings++;
		return (-1);
	}
	elsif ($str =~ /^ERROR/) {
		print STDERR $str;
		exit(1);
	}
	else {
		printf STDERR "ERROR Protocol failure (%d)\n", length($str);
		exit(1);
	}
}

#
# sign_file(credential, filename)
#
# Send the file to the server for signing. Package the file into a
# ZIP archive, send to the server, and extract the ZIP archive that
# is returned. The input ZIP archive always contains a single file,
# but the returned archive may contain one or more files.
#
sub sign_file {
	my ($cred, $path) = @_;
	my ($res, $size);

	$path =~ s:^\./::g; # remove leading "./"
	unlink("$Tmpdir/in.zip");
	system("cd $Indir; /usr/bin/zip -q $Tmpdir/in.zip $path");

	sendfile("$Tmpdir/in.zip", "$cred $path") || return;

	$res = <SRV_OUT>;
	$size = check_response($res);
	if ($size > 0) {
		recvfile("$Tmpdir/out.zip", $size) || return;
		
		if (system("cd $Outdir; /usr/bin/unzip -qo $Tmpdir/out.zip")) {
			$Warnings++;
		} else {
			print "$cred\t$path\n" unless $Quiet;
		}
	}
}

#
# sendfile(file, args)
#
# Send a ZIP archive file to the signing server. This involves
# sending a SIGN command with the given arguments, followed by
# the contents of the archive itself.
#
sub sendfile {
	my ($file, $args) = @_;
	my ($size, $bytes);

	$size = -s $file;
	print SRV_IN "SIGN $size $args\n";
	if (!open(F, "<$file")) {
		print STDERR "$file: $!\n";
		return (0);
	}
	read(F, $bytes, $size);
	close(F);
	if (!syswrite(SRV_IN, $bytes, $size)) {
		print STDERR "Can't send to server: $!\n";
		return (0);
	}
	return (1);
}

#
# recvfile(file, size)
#
# Receive a ZIP archive from the signing server. The caller
# provides the size argument previously obtained from the 
# server response.
#
sub recvfile {
	my ($file, $size) = @_;
	my $bytes;
	
	if (!read(SRV_OUT, $bytes, $size)) {
		print STDERR "Can't read from server: $!\n";
		return (0);
	}
	if (!open(F, ">$file")) {
		print STDERR "$file: $!\n";
		return (0);
	}
	syswrite(F, $bytes, $size);
	close(F);
	return (1);
}
