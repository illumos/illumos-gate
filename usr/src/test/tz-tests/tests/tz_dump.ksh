#!/usr/bin/ksh
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
# Copyright 2025 Oxide Computer Company
#

#
# The purpose of this program is to go through and dump the internal libc state
# from every time zone that we encounter so that we can go back and do a before
# an after comparison of this information.
#

unalias -a
set -o pipefail
export LANG=C.UTF-8

lc_arg0=$(basename $0)
lc_dir=$(dirname $0)
lc_print="*lclzonep::print -tL struct state"
lc_prev=
lc_out=
lc_libc=0
lc_zdump=0
lc_prog=${ZDUMP:-/usr/sbin/zdump}

#
# These will be filled in with the variable size that we detect via a program so
# we can survive some changes in libc without as much pain.
#
lc_chars=
lc_times=

#
# List of timezones
#
lc_zones=

usage()
{
	typeset msg="$*"
	[[ -z "$msg" ]] || echo "$msg" >&2
	cat <<USAGE >&2
Usage:  $lc_arg0 [-c] [-z] -o dir
Dump information about all timezones to a directory.

	-c		dump state from inside of libc
	-o directory	dump data to output directory
	-z		dump zone with zdump(8)
USAGE
	exit 2
}

fatal()
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "lcx_arg0: $msg" >&2
        exit 1
}

get_tzparams()
{
	eval $($lc_dir/tzparams.64);
	[[ -z "$TZ_MAX_TIMES" ]] && "failed to get TZ_MAX_TIMES"
	[[ -z "$TZ_MAX_CHARS" ]] && "failed to get TZ_MAX_CHARS"

	lc_chars="$TZ_MAX_CHARS"
	lc_times="$TZ_MAX_TIMES"

	for i in {0..$((lc_times - 1))}; do
		lc_prev+="$lc_print prev[0t$i].std[] prev[0t$i].alt[]\n"
	done

	lc_zones=$($lc_dir/tzlist.64)
	[[ -z "$lc_zones" ]] && fatal "failed to get time zones"
}

dump_one()
{
	typeset tz="$1"
	typeset dir="$lc_out/$tz"

	if ! mkdir -p $dir; then
		fatal "failed to make output directory $dir"
	fi

	printf "Dumping %s\n" "$tz"
	if (( lc_libc != 0 )); then
		TZ=$tz mdb $lc_dir/tzload.32 > "$dir/libc-out.32" \
		    2>"$dir/libc-err.32" <<EOF
::bp mdb_hook
::run
*lclzonep::printf "name: [%s]\n" struct state zonename
*lclzonep::printf "alt0: [%s]\n" struct state default_tzname0
*lclzonep::printf "alt1: [%s]\n" struct state default_tzname1
$lc_print zonerules daylight default_timezone default_altzone
$lc_print leapcnt timecnt typecnt charcnt charsbuf_size
$lc_print chars | ::dump -r -l 0t$lc_chars
$(echo "$lc_prev")
$lc_print ats types ttis lsis last_ats_idx start_rule end_rule
\$q
EOF

		TZ=$tz mdb $lc_dir/tzload.64 > "$dir/libc-out.64" \
		    2>"$dir/libc-err.64" <<EOF
::bp mdb_hook
::run
*lclzonep::printf "name: [%s]\n" struct state zonename
*lclzonep::printf "alt0: [%s]\n" struct state default_tzname0
*lclzonep::printf "alt1: [%s]\n" struct state default_tzname1
$lc_print zonerules daylight default_timezone default_altzone
$lc_print leapcnt timecnt typecnt charcnt charsbuf_size
$lc_print chars | ::dump -r -l 0t$lc_chars
$(echo "$lc_prev")
$lc_print ats types ttis lsis last_ats_idx start_rule end_rule
\$q
EOF
	fi

	if (( lc_zdump != 0 )); then
		$lc_prog -v $tz 2>&1 >"$dir/zdump"
	fi
}

while getopts ":co:z" c $@; do
	case "$c" in
	c)
		lc_libc=1
		;;
	o)
		[[ ! -d "$OPTARG" ]] && fatal "$OPTARG is not a directory"
		lc_out="$OPTARG"
		;;
	z)
		lc_zdump=1
		;;
	:)
		usage "option requires an argument -- $OPTARG"
		;;
	*)
		usage "invalid option -- $OPTARG"
		;;
	esac
done

[[ -z "$lc_out" ]] && usage "missing required output directory"
(( lc_libc == 0 && lc_zdump == 0 )) && usage \
    "at least one of -c or -z is required"

get_tzparams
for z in $lc_zones; do
	dump_one "$z"
done
exit 0
