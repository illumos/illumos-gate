package onbld_elfmod_vertype;

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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# This perl module implements the rules used to categorize ELF versions
# for the core Solaris OS and related code repositories. Although this
# code fits logically into the onbld_elfmod module, it is maintained as
# a separate module in order to allow maintainers of other code to provide
# an implementation appropriate to their local conventions.
#
# By isolating the codebase specific details of ELF version names in this
# module and reporting the results via a fixed interface, we allow
# interface_check and interface_cmp to be written in a way that isolates
# them from the specific names that apply to a given body of code.
# Those tools allow you to substitute your own module in place of this one
# to customize their behavior.
#
# The types of versions understood by interface_check and interface_cmp
# fall into the following categories:
#
#	NUMBERED:	A public version that follows the standard numbering
#			convention of a known prefix (e.g. ILLUMOS_),
#			followed by 2 or 3 dot separated numeric values:
#
#				<PREFIX>major.minor[.micro]
#
#	PLAIN:		A public version that may or may not contain
#			numeric characters, but for which numeric characters
#			are not treated as such.
#
#	SONAME:		Base version with the same name as the object SONAME
#
#	PRIVATE:	A private version that follows the same rules as PLAIN.
#
#	UNKNOWN:	A version string that does not fit any of the
#			above categories
#
# The above categories are generic, in the sense that they apply to any
# code base. However, each code base will have different well known prefix
# and name strings that map to these categories. The purpose of this module
# is to map these special well known strings to the category they represent
# for the code base in question.
#

use strict;


## Category(Version, Soname)
#
# Return an array containing the category of ELF version represented
# by the given Version, and other category dependent information.
#
# entry:
#	Version - Version string to examine
#	Soname - Empty ('') string, or SONAME of object that contains the
#		given version if it is available. In some environments,
#		the valid versions depend on the particular object in
#		question. This argument can be used to customize the
#		results of this routine based on the object being analyzed.
#
# exit:
#	This routine returns an array to describe the type of version
#	encountered. Element [0] is always a string token that gives one
#	of the version categories described in the module header comment.
#	For types other than NUMBERED, this is the only element in the
#	return array.
#
#	NUMBERED versions receive a return array with additional values
#	describing the version:
#
#		( 'NUMBERED', cnt, prefix, major, minor[, micro])
#
#	If the version has 3 numberic values, cnt is 3, and micro
#	is present. If there are 2 numeric values, cnt is 2, and micro
#	is omitted.
#
sub Category {
	my ($Ver, $Soname) = @_;

	# For illumos, the SUNW_ or ILLUMOS_ prefix is used for numbered
	# public versions.
	if ($Ver =~ /^((?:SUNW|ILLUMOS)_)(\d+)\.(\d+)(\.(\d+))?/) {
		return ('NUMBERED', 3, $1, $2, $3, $5) if defined($5);
		return ('NUMBERED', 2, $1, $2, $3);
	}

	# Well known plain versions. In Solaris, these names were used
	# to tag symbols that come from the SVR4 underpinnings to Solaris.
	# Later additions are all in the NUMBERED form.
	return ('PLAIN')
	    if (($Ver =~ /^SYSVABI_1.[23]$/) || ($Ver =~ /^SISCD_2.3[ab]*$/));

	# The link-editor creates "base" versions using the SONAME of the
	# object to contain  linker generated symbols (_etext, _edata, etc.).
	return ('SONAME')
	    if ($Ver eq $Soname) && ($Soname ne '');

	# The convention is to use SUNWprivate and ILLUMOSprivate to indicate
	# private versions. They may have a numeric suffix, but the
	# number is not significant for ELF versioning other than being part
	# of a unique name.
	return ('PRIVATE')
	    if ($Ver =~ /^(SUNW|ILLUMOS)private(_[0-9.]+)?$/);

	# Anything else is a version we don't recognize.
	return ('UNKNOWN');
}


# Perl modules pulled in via 'require' must return an exit status.
1;
