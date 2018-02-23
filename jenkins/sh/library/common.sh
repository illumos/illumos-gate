#!/bin/bash

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
# Copyright (c) 2017 by Delphix. All rights reserved.
#

#
# We want the "die" function to kill the entire job, not just the
# current shell; "exit 1" by itself will not work in cases were we start
# a subshell such as:
#
# var=$(command_invoked_in_subshell arg1 arg2)
#
# So we set a signal handler for SIGTERM and remember the pid of the top
# level process so that the die function can always send it SIGTERM.
#
export __CI_DIE_TOP_PID=$$
trap "exit 1" TERM

function die() {
	local bold="\E[1;31m"
	local norm="\E[0m"

	local msg=$1
	echo -e "${bold}failed:${norm} $msg" >&2
	kill -s TERM $__CI_DIE_TOP_PID
	exit 1
}

function log() {
	local bold="\E[1m"
	local norm="\E[0m"

	local args=()
	for arg in "$@"; do
		args[${#args[*]}]="$arg"
	done

	echo -e "${bold}running:${norm} ${args[*]}" >&2
	"${args[@]}"
	return $?
}

function log_must() {
	local args=()
	for arg in "$@"; do
		args[${#args[*]}]="$arg"
	done

	log "${args[@]}" || die "${args[*]}"
	return 0
}

function log_mustnot() {
	local args=()
	for arg in "$@"; do
		args[${#args[*]}]="$arg"
	done

	log "${args[@]}" && die "${args[*]}"
	return 0
}

function check_env() {
	for variable in "$@"; do
		eval value=\$$variable
		if [[ -z "$value" ]]; then
			die "$variable must be non-empty"
		fi
	done
	return 0
}
