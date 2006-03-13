#!/bin/ksh
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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Given a header file, extract function prototypes and global variable
# declarations in a form that can be used in a mapfile.  The list of extracted
# functions and variables will be combined with a user-specified template to
# create a complete mapfile.
#
# Template
# --------
#
# The template contains two sections - the prologue, and the epilogue.  These
# sections are used, verbatim, as the beginning and the end of the mapfile.
# Sections begin and end with single-line comments whose sole contents are
# "/* BEGIN $section */" and "/* END $section */".
#
# Template example:
#
# /* BEGIN PROLOGUE */
# [ ... prologue goes here ... ]
# /* END PROLOGUE */
# /* BEGIN EPILOGUE */
# [ ... epilogue goes here ... ]
# /* END EPILOGUE */
#
# Selective Exportation
# ---------------------
#
# Some header files will have a public/private interface mix that is strongly
# biased towards private interfaces.  That is, of the interfaces declared by
# a given header file, the majority of them are private.  Only a small subset
# of interfaces are to be exported publicly.  Using Selective Exportation, a
# special comment is included in the header file, declaring to this script that
# only a subset of interfaces - those with a marking declared in the comment -
# should be included in the mapfile.  The marking is itself a special comment,
# whose format is declared using a directive like this:
#
# 	MAPFILE: export "Driver OK"
#
# Using the above directive, only those function prototypes and variable
# declarations with "/* Driver OK */" comments included in the mapfile.  Note
# that the comment must be at the end of the first line.  If the declaration
# spans multiple lines, the exportation comment must appear on the first line.
#
# Examples of functions selected for exportation:
#
# MAPFILE: export "Driver OK"
#
# extern int foo(int);		/* Driver OK */
# extern void bar(int, int,	/* Driver OK */
#     int, void *);
#
# Selective Exportation may not be used in the same file as Selective Exclusion.
#
# Selective Exclusion
# -------------------
#
# Selective Exclusion is to be used in cases where the public/private interface
# mix is reversed - where public interfaces greatly outnumber the private ones.
# In this case, we want to be able to mark the private ones, thus telling this
# script that the marked interfaces are to be excluded from the mapfile.
# Marking is accomplished via a process similar to that used for Selective
# Exportation.  A directive is included in a comment, and is formatted like
# this:
#
#	MAPFILE: exclude "Internal"
#
# Using the above directive, function prototypes and variable declarations with
# "/* Internal */" comments would be excluded.  Note that the comment must be at
# the end of the first line.  If the declaration spans multiple lines, the
# exclusion comment must appear on the first line.
#
# Examples of functions excluded from exportation:
#
# MAPFILE: exclude "Internal"
#
# extern int foo(int);		/* Internal */
# extern void bar(int, int,	/* Internal */
#	int, void *);
#
# Selective Exclusion may not be used in the same file as Selective Exportation.
#

function extract_prototypes
{
	typeset header="$1"
	typeset prefix="$2"

	nawk -v prefix="$prefix" <$header '
		/^.*MAPFILE: export \"[^\"]*\"$/ {
			if (protoexclude) {
				print "ERROR: export after exclude\n";
				exit(1);
			}
		
			sub(/^[^\"]*\"/, "");
			sub(/\"$/, "");

			exportmark=sprintf("/* %s */", $0);
			next;
		}

		/^.*MAPFILE: exclude \"[^\"]*\"$/ {
			if (protomatch) {
				print "ERROR: exclude after export";
				exit(1);
			}

			sub(/^[^\"]*\"/, "");
			sub(/\"$/, "");

			excludemark=sprintf("/* %s */", $0);
			next;
		}

		exportmark {
			# Selective Exportation has been selected (exportmark is
			# set), so exclude this line if it does not have the
			# magic export mark.
			if (length($0) < length(exportmark) ||
			    substr($0, length($0) - length(exportmark) + 1) != \
			    exportmark)
				next;
		}

		excludemark {
			# Selective Exclusion has been selected (excludemark is
			# set), so exclude this line only if it has the magic
			# exclude mark.
			if (length($0) > length(excludemark) &&
			    substr($0, \
			    length($0) - length(excludemark) + 1) == \
			    excludemark)
				next;
		}

		# Functions
		/^extern.*\(/ {
			for (i = 1; i <= NF; i++) {
				if (sub(/\(.*$/, "", $i)) {
					sub(/^\*/, "", $i);
					if (!seenfn[$i]) {
						printf("%s%s;\n", prefix, $i);
						seenfn[$i] = 1;
					}
					break;
				}
			}
			next;
		}

		# Global variables
		/^extern[^\(\)]*;/ {
			for (i = 1; i <= NF; i++) {
				if (match($i, /;$/)) {
					printf("%s%s; /* variable */\n", prefix,
					    substr($i, 1, length($i) - 1));
					break;
				}
			}
			next;
		}
	' || die "Extraction failed"
}

function extract_section
{
	typeset skel="$1"
	typeset secname="$2"

	nawk <$skel -v name=$secname -v skel=$skel '
	    /\/\* [^ ]* [^ ]* \*\// && $3 == name {
		if ($2 == "BEGIN") {
			printing = 1;
		} else {
			printing = 0;
		}
		next;
	    }

	    printing != 0 { print; }
	'
}

function die
{
	echo "$PROGNAME: $@" >&2
	exit 1
}

function usage
{
	echo "Usage: $PROGNAME -t tmplfile header [header ...]" >&2
	exit 2
}

PROGNAME=$(basename "$0")

while getopts t: c ; do
	case $c in
	    t)
		mapfile_skel=$OPTARG
		;;
	    ?)
		usage
	esac
done

[[ -z "$mapfile_skel" ]] && usage
[[ ! -f $mapfile_skel ]] && die "Couldn't open template $tmplfile"

shift $(($OPTIND - 1))

[[ $# -lt 1 ]] && usage

for file in $@ ; do
	[[ ! -f $file ]] && die "Can't open input file $file"
done

extract_section $mapfile_skel PROLOGUE

for file in $@ ; do
	echo "\t\t/*"
	echo "\t\t * Exported functions and variables from:"
	echo "\t\t *  $file"
	echo "\t\t */"
	extract_prototypes $file "\t\t"
	echo
done

extract_section $mapfile_skel EPILOGUE
