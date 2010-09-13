#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/
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
BEGIN	{
	MAXCPU = 20.		# report if cpu usage is greater than this
	MAXKCORE = 500.		# report is Kcore usage is greater than this
	MAXCONNECT = 120.	# report if connect time is greater than this
}

NR == 1	 {
	MAXCPU = MAXCPU + 0
	MAXKCORE = MAXKCORE + 0
	MAXCONNECT = MAXCONNECT + 0
	printf "Logins with exceptional Prime/Non-prime Time Usage\n"
	printf ( "CPU > %d or KCORE > %d or CONNECT > %d\n\n\n", MAXCPU, MAXKCORE, MAXCONNECT)
	printf "\tLogin\t\tCPU (mins)\tKCORE-mins\tCONNECT-mins\tdisk"
	printf "\t# of\t# of\t# Disk\tfee\n"
	printf "UID\tName\t\tPrime\tNprime\tPrime\tNprime\t"
	printf "Prime\tNprime\tBlocks\tProcs\tSess\tSamples\n\n"
}

$3 > MAXCPU || $4 > MAXCPU || $5 > MAXKCORE || $6 > MAXKCORE || $7 > MAXCONNECT || $8 > MAXCONNECT {
	printf("%d\t%-8.8s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
}

