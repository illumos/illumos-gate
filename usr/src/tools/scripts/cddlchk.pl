#!/usr/perl5/bin/perl
#
# See the bottom of the file for the license, and for the reason why it is
# there and not here.
#

#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Check source files for a valid CDDL block.
#

use strict;
use warnings;
use Getopt::Std;
use Pod::Usage;
use File::Find;

#
# Global variables.
#

our $VERSION = '%I%';		# Program version number.

our $CmtChrs = q{#*!/\";.};	# Acceptable comment characters.
our %Opt;			# Command-line flags.
our @CDDL;			# Approved CDDL block.
our $CDDLStartRE;		# RE to match the first line of a CDDL block.
our $CDDLEndRE;			# RE to match the last line of a CDDL block.
our $Status = 0;		# Exit status
our $CmtRE;			# Comment regular expression.
our %IgnoreDir;			# Directories to be ignored.
our %IgnoreFile;		# Files to be ignored.
our $IgnoreExtnRE;		# File extensions to be ignored.

#
# Print a help message - see Getopt::Std.
#
sub HELP_MESSAGE
{
	my ($out, $opt_pkg, $ver, $sw) = @_;
	pod2usage(-output => $out, -exitval => 2, -verbose => 2);
}

#
# Print a version message - see Getopt::Std.
#
sub VERSION_MESSAGE
{
	my ($out, $opt_pkg, $ver, $sw) = @_;
	print($out "cddlchk version $VERSION\n");
}

#
# Print a message.
#
sub message
{
	print("Message: ", join("\n         ", @_), "\n");
}

#
# Print a warning message.
#
sub warning
{
	print("Warning: ", join("\n         ", @_), "\n");
	$Status = 2 if ($Status == 0);
}

#
# Print an error message.
#
sub error
{
	print("Error: ", join("\n    ", @_), "\n");
	$Status = 1;
}

#
# Load an exceptions file.  $root, if specified, will be prepended to all
# relative file and directory paths.  Exceptions may be one of three types:
#     1. File paths.
#     2. Directories, specified with a trailing '/'.
#     3. File extensions, specified with a leading '*.'
# Returns true if the file loaded OK, false otherwise.
#
sub load_exceptions
{
	my ($file, $root) = @_;

	# Fix up the $root prefix, if specified.
	$root .= '/' if (defined($root) && substr($root, -1, 1) ne '/');

	# Open the exception file.
	my $fh;
	if (! open($fh, '<', $file)) {
		return(0);
	}

	# Zero any existing exceptions, read the file.
	%IgnoreDir = ();
	%IgnoreFile = ();
	$IgnoreExtnRE = undef;
	my @ext;
	while (defined(my $line = <$fh>)) {
		chomp($line);
		# File extension.
		if ($line =~ m{^\*\.(.*)$}) {
			push(@ext, quotemeta($1));

		# Directory path.
		} elsif (($_) = $line =~ m{^(.*)/$}) {
			$_ = "$root$_"
			    if (defined($root) && substr($_, 0, 1) ne '/');
			$IgnoreDir{$_} = 1;

		# File path.
		} else {
			$line = "$root$line"
			    if (defined($root) && substr($line, 0, 1) ne '/');
			$IgnoreFile{$line} = 1;
		}
	}

	# Compose the extension exception RE if any were defined.
	if (@ext > 0) {
		$_ = '\.(?:' . join('|', @ext) . ')$';
		$IgnoreExtnRE = qr{$_};
	}

	return(close($fh));
}

#
# Check if the specified file or directory should be validated or not.
# $type is 'file' or 'dir'.
#
sub is_exception
{
	my($type, $path) = @_;

	if ($type eq 'file') {
		return(exists($IgnoreFile{$path}) ||
		    (defined($IgnoreExtnRE) && $path =~ $IgnoreExtnRE));
	} else {
		return(exists($IgnoreDir{$path}));
	}
}

#
# Check a file for a valid CDDL block.  If $Opt{a} is true an error will be
# reported if the file doesn't contain any CDDL at all, if it is false a
# warning will only be reported if the file has a CDDL block which is invalid.
# If $Opt{v} is true valid files will be listed, otherwise they will not.
#
sub cuddle
{
	my ($file) = @_;

	# Open the file.
	my $fh;
	if (! open($fh, '<', $file)) {
		error("Can't open $file: $!");
		return;
	}

	# Extract all the CDDL blocks.
	my ($msg, $start, $block, @cddl);
	$msg = 0;
	$block = [];
	while (defined($_ = <$fh>)) {
		if (my $s = $_ =~ $CDDLStartRE ... $_ =~ $CDDLEndRE) {
			chomp($_);
			push(@$block, $_);
			# First line of CDDL block.
			if ($s == 1) {
				$start = $.;
			# Last line of CDDL block.
			} elsif (substr($s, -2) eq 'E0') {
				push(@cddl,
				    { start => $start, block => $block });
				$start = undef;
			$block = [];
			}
		}
	}

	# Close the file.
	if (! close($fh)) {
		warning("Can't close $file: $!");
	}

	# Check for unterminated blocks.
	if (defined($start)) {
		error("Unterminated CDDL block in file $file",
		    "at line $start");
		$msg++;
	}

	# Check for no CDDL - may be a warning.
	if (@cddl == 0 && $Opt{a}) {
		warning("No CDDL block in file $file");
		return;
	}

	# Check for multiple CDDL blocks.
	if (@cddl > 1) {
		error("Multiple CDDL blocks in file $file",
		    "at lines " . join(", ", map($_->{start}, @cddl)));
		$msg++;
	}

	# Validate each CDDL block.
	foreach my $c (@cddl) {
		my ($s, $b) = @$c{qw{start block}};

		# Compare each line.
		for (my $i = 0; $i < @CDDL; $i++) {
			$_ = $i < @$b ? $b->[$i] : '';
			if ($_ !~ m{^$CmtRE\Q$CDDL[$i]\E$}) {
				error(
				    "Invalid line in CDDL block in file $file",
				    "at line " . ($s + $i) . ", should be",
				    "'[$CmtChrs ]*$CDDL[$i]'", "is", "'$_'");
				$msg++;
				last;	# Just report the first error.
			}
		}
	}

	# Report the file if required.
	message("Valid CDDL block in file $file") if ($Opt{v} && ! $msg);
}

#
# Main.
#

# Check the command-line arguments.
$Getopt::Std::STANDARD_HELP_VERSION = 1;
pod2usage() unless (getopts('avx:M', \%Opt));
pod2usage(-verbose => 2) if ($Opt{M});

# Read in the exception list.
if (exists($Opt{x})) {
	if (! load_exceptions($Opt{x})) {
		error("Can't load exceptions file $Opt{x}: $!");
		exit(2);
	}
}

# Read in the template CDDL block from the end of the file.
while (defined($_ = <DATA>)) {
	chomp($_);
	push(@CDDL, $_);
}
shift(@CDDL) while ($CDDL[0] =~ m{^\s*$});
pop(@CDDL) while ($CDDL[$#CDDL] =~ m{^\s*$});
$CmtRE = qr{[\Q$CmtChrs\E\s]*};
$CDDLStartRE = qr{^$CmtRE\Q$CDDL[0]};
$CDDLEndRE = qr{^$CmtRE\Q$CDDL[$#CDDL]};

# File::Find callback.
my $wanted = sub {
	my $path = $File::Find::name;
	if (-d $path && $path =~ m{SCCS$}) {
		$File::Find::prune = 1;
	} elsif (-f _) {
		cuddle($path) unless (is_exception('file', $path));
	}
};

# Process each file and directory on the command-line.
foreach my $arg (@ARGV) {
	if (-f $arg) {
		# Explicitly listed files must have a CDDL block.
		cuddle($arg, 1) unless (is_exception('file', $arg));
	} elsif (-d $arg) {
		find({ wanted => $wanted, no_chdir => 1 }, $arg)
		    unless (is_exception('dir', $arg));
	} else {
		error("Unrecognised file/directory argument $arg");
	}
}
exit($Status);

#
# Inline documentation.
#

=pod

=head1 NAME

cddlchk - Check for valid CDDL blocks

=head1 SYNOPSIS

cddlchk [B<-avxM> B<--help> B<--version>] [B<<file or directory>>...]

=head1 DESCRIPTION

cddlchk inspects files for missing, obsolete, or corrupt CDDL blocks.

=head1 OPTIONS

The following options are supported:

=over

=item B<-a>

Check that all the specified files have a CDDL block, and report a warning if
they do not.  If this flag is not specified, only files containing an existing
CDDL block are validated.

=item B<-v>

Report on all files, not just those with invalid headers.

=item B<-x>

Load an exceptions file containing a list of files, directories and file
extensions to be ignored.  Exceptions may be one of three types:

=over

=item * B<File paths>

=item * B<Directories>, specified with a trailing C</>

=item * B<File extensions>, specified with a leading C<*.>

=back

=item B<-M>

Display the manpage for the chkcddl command.

=item B<--help>

Display command-line help for the cddlchk command.

=item B<--version>

Display the program version number.

=back

=head1 EXIT STATUS

The following exit status values are returned:

=over

=item B<0>

The command completed sucessfully.  No errors or warnings were reported.

=item B<1>

The command completed unsucessfully.  One or more errors or warnings were
reported.

=item B<2>

Invalid command-line arguments were specified to the command, or one of the
command-line help functions was invoked.

=back

=cut

#
# Put the CDDL at the end of the file so we can use it as a template.
#

__DATA__

CDDL HEADER START

The contents of this file are subject to the terms of the
Common Development and Distribution License (the "License").
You may not use this file except in compliance with the License.

You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
or http://www.opensolaris.org/os/licensing.
See the License for the specific language governing permissions
and limitations under the License.

When distributing Covered Code, include this CDDL HEADER in each
file and include the License file at usr/src/OPENSOLARIS.LICENSE.
If applicable, add the following below this CDDL HEADER, with the
fields enclosed by brackets "[]" replaced with your own identifying
information: Portions Copyright [yyyy] [name of copyright owner]

CDDL HEADER END
