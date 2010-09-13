#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/
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
BEGIN {
	MAXCPU = 20.0		# report if cpu usage greater than this
	MAXKCORE = 1000.0	# report if KCORE usage is greater than this
}

NF == 4	{ print "\t\t\t\t" $1 " Time Exception Command Usage Summary" }

NF == 3	{ print "\t\t\t\tCommand Exception Usage Summary" }

NR == 1	{
	MAXCPU = MAXCPU + 0.0
	MAXKCORE = MAXKCORE + 0.0
	print "\t\t\t\tTotal CPU > " MAXCPU " or Total KCORE > " MAXKCORE
}

NF <= 4 && length != 0	{ next }

$1 == "COMMAND" || $1 == "NAME"	{ print; next }

NF == 10 && ( $4 > MAXCPU || $3 > MAXKCORE ) && $1 != "TOTALS"

NF == 13 && ( $5 + $6 > MAXCPU || $4 > MAXKCORE ) && $1 != "TOTALS"

length == 0


