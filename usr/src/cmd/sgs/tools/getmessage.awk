#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Extract MACROs referenced by MSG_INTL and MSG_ORIG
#	The MACROS referenced by MSG_INTL() go to MSG_INTL_LIST
#	The MACROS referenced by MSG_ORIG() go to MSG_ORIG_LIST
#

BEGIN {
	FS = "[,(){]|[ ]+|[\t]+"

	# These variables are used to handle the lines such as:
	#		MSG_INTL(
	#		MSG_FORMAT);
	watchme_intl = 0
	watchme_orig = 0
}

#
# If the input line has MSG_INTL or MSG_ORIG, collect the
# MACRO used. Assumption is that the MACRO names have to be
# composed of upper characters.
#
/MSG_INTL|MSG_ORIG|_elf_seterr/ {
	for (i = 1; i <= NF; ++i) {
		if ($i == "MSG_INTL" || $i == "_elf_seterr") {
			if (i == NF - 1) {
				watchme_intl = 1
				next
			}
			j = i + 1
			while ($j == "")
				j++
			if (match($j, /[a-z]/) == 0 &&
			    match($j, /[A-Z]/) != 0) 
				print $j	> "MSG_INTL_LIST"
		}

		if ($i == "MSG_ORIG") {
			if (i == NF - 1) {
				watchme_orig = 1
				next
			}
			j = i + 1
			while ($j == "")
				j++
			if (match($j, /[a-z]/) == 0 &&
			    match($j, /[A-Z]/) != 0) 
				print $j	> "MSG_ORIG_LIST"
		}
	}
}

#
# If the previous line ended with MSG_INTL or MSG_ORIG not
# having the MACRO name, pick it from the next line.
#
{
	if (watchme_intl == 1) {
		if (match($1, /[a-z]/) == 0 &&
		    match($1, /[A-Z]/) != 0) 
			print $1	> "MSG_INTL_LIST"
		watchme_intl = 0;
	} else if (watchme_orig == 1) {
		if (match($1, /[a-z]/) == 0 &&
		    match($1, /[A-Z]/) != 0) 
			print $1	> "MSG_INTL_ORIG"
		watchme_orig = 0;
	}
}
