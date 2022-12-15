#! /usr/bin/sh
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

# Copyright 2023 Richard Lowe

# find_in_group <group> <section> <file>
# errors if not present, else returns the group index
find_in_group() {
	elfdump -g $3 | awk -v group="${1}\$" -v section=$2 '
		BEGIN { slurp = 0 };
		$0 ~ group { slurp = 1 };
		slurp && $0 ~ section {
			gsub(/[\[\]]/, "", $3);
			print $3;
			exit;
		}' | read index
	if [[ -z $index ]] || (( index <= 0 )); then
		print -u2 "Couldn't find $2 in $1"
		exit 1
	fi
	print $index;
}
