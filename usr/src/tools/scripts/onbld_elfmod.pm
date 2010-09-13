package onbld_elfmod;

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

#
# This perl module contains code shared between the ELF analysis
# tools found in this directory: find_elf, check_rtime, interface_check,
# and interface_cmp.
#

use strict;
use File::Basename;

## GetLine(FileHandleRef, LineNumRef)
#
# Read the next non-empty line from the given file handle reference
# and return it.
#
# entry:
#	FileHandleRef - Reference to open file handle to read from
#	LineNumRef - Reference to integer to increment as lines are input
#
sub GetLine {
	my ($fh, $LineNum) = @_;
	my $ret_line = '';
	my $line;
	my $cont = 1;

	while ($cont && ($line = <$fh>)) {
		$$LineNum++;
		chomp $line;

		# A backslash at the end of the line indicates that the
		# following line is a continuation of this line if the
		# backslash is the only character on the line, or if it is
		# preceded by a space.
		next if ($line eq '\\');
		$cont = ($line =~ s/\s+\\$//);

		# The # character starts a comment if it is the first
		# character on the line, or if it is preceeded by a space.
		if ($line =~ /^\#/) {
			$cont = 1;
			next;
		}
		$line =~ s/\s+\#.*$//;		# Strip Comments
		$line =~ s/\s*$//;		# Trailing whitespace

		if ($line !~ /^\s*$/) {		# Non-empty string
			$line =~ s/^\s+//;	# Leading whitespace
			if ($ret_line eq '') {
				$ret_line = $line;
			} else {
				$ret_line = "$ret_line $line";
			}
		}

		# If our result string is still null, act as if a 
		# continuation is present and read another line.
		$cont = 1 if ($ret_line eq '');
	}

	# The above loop won't exit while $ret_line is a null string
	# unless the read failed, so return undef() in that case.
	# Otherwise, use the value in $ret_line.
	return ($ret_line ne '') ? $ret_line : undef();
}


## LoadExceptionsToEXRE(name)
#
# Locate the exceptions file and process its contents. This function can be
# used by any program with exception files that consist of a single
# verb, followed by a single regular expression:
#
#	VERB regex
#
# For each such verb, the global level of the main:: namespace must
# have a variable named $EXRE_verb. The $EXRE_ prefix must only be used
# for these variables, and not for any other. The caller must define these
# variables, but leave them undefined.
#
# entry:
#	Any variables in the main:: global symbol table starting with
#	the prefix 'EXRE_xxx' are taken to represent the regular expression
#	for the exception named xxx.
#
#	name - Name of script (i.e. 'check_rtime')
#	$main::opt{e} - Calling program must accept a '-e' option
#		that allows the user to specify an exception file
#		to use, and the value of that option must be found
#		in $main::opt{e}.
#
# exit:
#	The $main::EXRE_xxx variables are updated to contain any regular
#	expressions specified by the exception file. If a given exception
#	is not encountered, its variable is not modified.
#
# note:
#	We expand strings of the form MACH(dir) to match the given
#	directory as well as any 64-bit architecture subdirectory that
#	might be present (i.e. amd64, sparcv9).
# 
sub LoadExceptionsToEXRE {
	my $name = $_[0];
	my $file;
	my $Line;
	my $LineNum = 0;
	my $err = 0;
	my %except_names = ();
	my %except_re = ();

	# Examine the main global symbol table and find all variables
	# named EXRE_xxx. By convention established for this program,
	# all such variables contain the regular expression for the
	# exception named xxx.
	foreach my $entry (keys %main::) {
		$except_names{$entry} = 1 if $entry =~ /^EXRE_/;
	}

	# Locate the exception file
	FILE: {
		# If -e is specified, that file must be used
		if ($main::opt{e}) {
			$file = $main::opt{e};
			last FILE;
		}

		# If this is an activated workspace, use the exception
		# file found in the exceptions_list directory.
		if (defined($ENV{CODEMGR_WS})) {
			$file = "$ENV{CODEMGR_WS}/exception_lists/$name";
			last FILE if (-f $file);
		}

		# As a final backstop, the SUNWonbld package provides a
		# copy of the exception file. This can be useful if we
		# are being used with an older workspace.
		#
		# This script is installed in the SUNWonbld bin directory,
		# while the exception file is in etc/exception_lists. Find
		# it relative to the script location given by $0.
		$file = dirname($0) . "/../etc/exception_lists/$name";
		last FILE if (-f $file);

		# No exception file was found.
		return;
	}

	open (EFILE, $file) ||
		die "$name: unable to open exceptions file: $file";
	while ($Line = onbld_elfmod::GetLine(\*EFILE, \$LineNum)) {
		# Expand MACH()
		$Line =~ s/MACH\(([^)]+)\)/$1(\/amd64|\/sparcv9)?/;

		# %except_re is a hash indexed by regular expression variable
		# name, with a value that contains the corresponding regular
		# expression string. If we recognize an exception verb, add
		# it to %except_re.
		if ($Line =~ /^\s*([^\s]+)\s+(.*)$/i) {
			my $verb = $1;
			my $re = $2;

			$verb =~ tr/A-Z/a-z/;
			$verb = "EXRE_$verb";
			if ($except_names{$verb}) {
				if (defined($except_re{$verb})) {
					$except_re{$verb} .= '|' . $re;
				} else {
					$except_re{$verb} = $re;
				}
			}
			next;
		}

		$err++;
		printf(STDERR "$file: Unrecognized option: ".
		    "line $LineNum: $Line\n");
	}
	close EFILE;

	# Every exception that we encountered in the file exists
	# in %except_re. Compile them and assign the results into the
	# global symbol of the same name.
	#
	# Note that this leaves the global symbols for unused exceptions
	# untouched, and therefore, undefined. All users of these variables
	# are required to test them with defined() before using them.
	foreach my $verb (sort keys %except_names) {
		next if !defined($except_re{$verb});

		# Turn off strict refs so that we can do a symbolic
		# indirection to set the global variable of the name given
		# by verb in the main namespace. 'strict' is lexically scoped,
		# so its influence is limited to this enclosing block.
		no strict 'refs';
		${"main::$verb"} = qr/$except_re{$verb}/;
	}

	exit 1 if ($err != 0);
}


## OutMsg(FileHandleRef, Ttl, obj, msg)
## OutMsg2(FileHandleRef, Ttl, old_obj, new_obj, msg)
#
# Create an output message, either a one-liner (under -o) or preceded by the
# files relative pathname as a title.
#
# OutMsg() is used when issuing a message about a single object.
#
# OutMsg2() is for when the message involves an old and new instance
# of the same object. If old_obj and new_obj are the same, as is usually
# the case, then the output is the same as generated by OutMsg(). If they
# differ, as can happen when the new object has changed names, and has been
# found via an alias, both the old and new names are shown.
#
# entry:
#	FileHandleRef - File handle to output file
#	Ttl - Reference to variable containing the number of times
#		this function has been called for the current object.
#	obj - For OutMsg, the path for the current object
#	old_obj, new_obj - For OutMsg2, the names of the "old" and "new"
#		objects.
#	msg - Message to output
#
#	$main::opt{o} - Calling program must accept a '-o' option
#		that allows the user to specify "one-line-mode',
#		and the value of that option must be found
#		in $main::opt{o}.
#
sub OutMsg {
	my($fh, $Ttl, $obj, $msg) = @_;

	if ($main::opt{o}) {
		print $fh "$obj: $msg\n";
	} else {
		print $fh "==== $obj ====\n" if ($$Ttl++ eq 0);
		print $fh "\t$msg\n";
	}
}

sub OutMsg2 {
	my ($fh, $Ttl, $old_obj, $new_obj, $msg) = @_;

	# If old and new are the same, give it to OutMsg()
	if ($old_obj eq $new_obj) {
		OutMsg($fh, $Ttl, $old_obj, $msg);
		return;
	}

	if ($main::opt{o}) {
		print "old $old_obj: new $new_obj: $msg\n";
	} else {
		print "==== old: $old_obj / new: $new_obj ====\n"
		    if ($$Ttl++ eq 0);
		print "\t$msg\n";
	}
}


## header(FileHandleRef, ScriptPath, Argv)
#
# Generate a header for the top of generated output, including a copyright
# and CDDL, such that the file will pass ON copyright/CDDL rules if it is
# checked into the repository.
#
# entry:
#	FileHandleRef - File handle reference to output text to
#	ScriptPath - Value of $0 from caller, giving path to running script
#	Argv - Reference to array containing @ARGV from caller.
#
# note:
#	We assume that the calling script contains a value CDDL block.
#
sub Header {

	my ($fh, $ScriptPath, $Argv) = @_;
	my $year = 1900 + (localtime())[5];

	print $fh "#\n";
	print $fh "# Copyright $year Sun Microsystems, Inc.  ",
	    "All rights reserved.\n";
	print $fh "# Use is subject to license terms.\n#\n";

	# The CDDL text is copied from this script, the path to which is
	# assigned to $0 by the Perl interpreter.
	if (open(CDDL, $ScriptPath)) {
		my $out = 0;
		my $Line;

		while ($Line = <CDDL>) {
			$out = 1 if ($Line =~ /^\# CDDL HEADER START/);

			print $fh $Line if $out;
			last if ($Line =~ /^\# CDDL HEADER END/);
		}
		print $fh "#\n\n";
		close CDDL;
	}

	print $fh '# Date:    ', scalar(localtime()), "\n";
	$ScriptPath =~ s/^.*\///;
	$ScriptPath =~ s/\.pl$//;
	print $fh "# Command: $ScriptPath ", join(' ', @$Argv), "\n\n";
}

# Perl modules pulled in via 'require' must return an exit status.
1;
