#!/usr/perl5/bin/perl -w
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#ident	"%Z%%M%	%I%	%E% SMI"

# Check that header files conform to our standards
#
# Usage: hdrck [-a] file [file ...]
#
#	-a	Apply (more lenient) application header rules
#
# Standards for all header files:
#
#	1) Begin with a comment containing a copyright message
#
#	2) Enclosed in a guard of the form:
#
#	   #ifndef GUARD
#	   #define GUARD
#	   #endif /* [!]GUARD */
#
#	   The preferred form is without the bang character, but either is
#	   acceptable.
#
#	3) Has a valid ident declaration
#
# Additional standards for system header files:
#
#	1) The file guard must take the form '_FILENAME_H[_]', where FILENAME
#	   matches the basename of the file.  If it is installed in a
#	   subdirectory, it must be of the form _DIR_FILENAME_H.  The form
#	   without the trailing underscore is preferred.
#
#	2) All #include directives must use the <> form.
#
#	3) If the header file contains anything besides comments and
#	   preprocessor directives, then it must be enclosed in a C++ guard of
#          the form:
#
#	   #ifdef __cplusplus
#	   extern "C" {
#	   #endif
#
#	   #ifdef __cplusplus
#	   }
#	   #endif
#

use File::Basename;

$do_system = 1;

if ($#ARGV >= 0) {
	if ($ARGV[0] eq "-a") {
		$do_system = 0;
		shift;
	}
}

#
# Global varibles keep track of what file we're processing and what line we're
# on.
#

my $lineno;
my $filename;
my $feof;
my $exitval = 0;

#
# Loop through each file on the command line and process it appropriately
#
while ($filename = shift) {

	if (!open FILE, $filename) {
		print STDERR "failed to open '$filename': $!\n";
		next;
	}

	$feof = 0;
	$lineno = 0;

	process_file();
	
	close FILE;
}

exit $exitval;

#
# Returns the next line from the file, skipping blank lines.
#
sub getline {
	my $line;

	while ($line = <FILE>) {
		$lineno++;
		chop $line;
		if ($line =~ /^.+$/) {
			return $line;
		}
	}
	
	$feof = 1;
	return $line;
}

#
# Prints out an error message with the current file and line number
#
sub error {
	my $msg = shift;
	if ($feof) {
		print STDERR "$filename: $msg\n";
	} else {
		print STDERR "$filename: line $lineno: $msg\n";
	}
	$exitval++;
}

#
# The main verification process
#
sub process_file {

	my $eolcom = '(.*/\*\s.*\s\*/)?';
	my $found_ident = 0;

	my $ident = '(\%Z\%(\%M\%)\t\%I\%|\%W\%)\t\%E\% SMI';
	my $xident = '@\(#\)(\w[-\.\w]+\.h)\t\d+\.\d+(\.\d+\.\d+)?\t\d\d/'.
	    '\d\d/\d\d SMI';

	#
	# Step 1: 
	#
	# Headers must begin with a comment containing a copyright notice.  We
	# don't validate the contents of the copyright, only that it exists.
	#
	$_ = skip_comments();
	if (!$found_copyright) {
		error("Missing copyright in opening comment");
	}

	#
	# Step 2:
	#
	# For application header files only, allow the ident string to appear
	# before the header guard.
	#
	if (!$do_system &&
	    /^#pragma ident\t\"(($xident)|($ident))\"$eolcom\s*$/) {
		$found_ident = 1;
		$_ = skip_comments();
	}

	#
	# Step 3: Header guards
	#
	my $guard = "NOGUARD";
	if (!/^#ifndef\s([a-zA-Z_0-9]+)$/) {
		error("Invalid or missing header guard");
	} else {
		$guard = $1;

		if ($do_system) {
			my $guardname = basename($filename);
			
			#
			# For system headers, validate the name of the guard
			#
			$guardname =~ tr/a-z/A-Z/;
			$guardname =~ tr/\./_/;
			$guardname =~ tr/-/_/;

			if (!($1 =~ /^_.*$guardname[_]?$/)) {
				error("Header guard does not match filename");
			}

		}

		$_ = getline();
		if (!/^#define\s$1$/) {
			error("Invalid header guard");
			if (/^$/) {
				$_ = skip_comments();
			}
		} else {
			$_ = skip_comments();
		}
	}

	#
	# Step 4: ident string
	#
	# We allow both the keyword and extracted versions.
	#
	if (!$found_ident) {
		if (!/^#pragma ident\t\"(($xident)|($ident))\"$eolcom\s*$/) {
			error("Invalid or missing #pragma ident");
		} else {
			$_ = skip_comments();
		}
	}

	#
	# Main processing loop.
	#
	my $in_cplusplus = 0;
	my $found_endguard = 0;
	my $found_cplusplus = 0;
	my $found_code = 0;

	while ($_) {

		if (!/^#/ && !/^using /) {
			$found_code = 1;
		}

		if (/^#include(.*)$/) {
			#
			# Validate #include directive.  For system files, make
			# sure its of the form '#include <>'.
			#
			if ($do_system && !($1 =~ /\s<.*>/)) {
				error("Bad include");
			}
		} elsif (!$in_cplusplus && /^#ifdef\s__cplusplus$/) {

			#
			# Start of C++ header guard.  Make sure it of the form:
			#
			# #ifdef __cplusplus
			# extern "C" {
			# endif
			#
			$_ = getline();
			if (/^extern "C" {$/) {
				$_ = getline();
				if (!/^#endif$/) {
					error("Bad _cplusplus clause");
				} else {
					$in_cplusplus = 1;
					$found_cplusplus = 1;
				}
			} else {
				next;
			}
		} elsif ($in_cplusplus && /^#ifdef\s__cplusplus$/) {

			#
			# End of C++ header guard.  Make sure it's of the form:
			#
			# #ifdef __cplusplus
			# }
			# #endif
			#
			$_ = getline();
			if (/^}$/) {
				$_ = getline();
				if (!/^#endif$/) {
					error("Bad __cplusplus clause");
				} else {
					$in_cplusplus = 0;
				}
			} else {
				next;
			}
		} elsif (/^#endif\s\/\* [!]?$guard \*\/$/){

			#
			# Ending header guard
			#
			$found_endguard = 1;

		} 

		$_ = skip_comments();
	}

	#
	# Check for missing end clauses
	#
	if ($do_system && !$found_cplusplus && $found_code) {
		error("Missing __cplusplus guard");
	}

	if ($in_cplusplus) {
		error("Missing closing #ifdef __cplusplus");
	}

	if (!$found_endguard) {
		error("Missing or invalid ending header guard");
	}
}


#
# Skips comments, returning the next line after the comment.  This only avoids
# lines which begin with comments.  Any other partial comment lines are returned
# unaltered.
#
# It can set one of the following global variables:
#
#	found_copyright		Comment contains copyright string
#
sub skip_comments {
	my $sub = shift;
	my $open_comment = '/\*';
	my $close_comment = '\*/';

	$found_copyright = 0;

	while ($_ = getline()) {

		# For application headers, allow C++ comments
		if (!$do_system && /^\s*\/\//) {
			next;
		}

		# Not a comment
		if (!/^\s*\/\*/) {
			return $_;
		}

		while (!/\*\//) {
			if (/Copyright/) {
				$found_copyright = 1;
			}

			$_ = getline();
		}

		if (/Copyright/) {
			$found_copyright = 1;
		} 
	}

	# Join continuation lines
	if ($_) {
		while (/\\$/) {
			chop;
			$_ .= getline();
		}
	}

	return $_;
}
