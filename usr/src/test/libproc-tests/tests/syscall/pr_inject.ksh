#!/usr/bin/ksh
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

#
# Copyright 2024 Oxide Computer Company
#

#
# This runs the specific tests around the pr_inject tests.
#

unalias -a
set -o pipefail

pr_arg0=$(basename $0)
pr_dir=$(dirname $0)
pr_inj32="$pr_dir/pr_inject.32"
pr_inj64="$pr_dir/pr_inject.64"
pr_targ32="$pr_dir/pr_target.32"
pr_targ64="$pr_dir/pr_target.64"
pr_exit=0

printf "Running 32-bit controller against 32-bit target\n"
if ! $pr_inj32 $pr_targ32; then
	pr_exit=1
fi

printf "\nRunning 64-bit controller against 32-bit target\n"
if ! $pr_inj64 $pr_targ32; then
	pr_exit=1
fi

printf "\nRunning 64-bit controller against 64-bit target\n"
if ! $pr_inj64 $pr_targ64; then
	pr_exit=1
fi


if (( pr_exit == 0 )); then
	printf "All variants passed successfully\n"
fi

exit $pr_exit
