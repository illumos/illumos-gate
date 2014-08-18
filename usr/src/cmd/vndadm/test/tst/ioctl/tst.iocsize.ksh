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
# Copyright (c) 2014 Joyent, Inc.  All rights reserved.
#

#
# Ensure structure sizes for both ILP32 and LP64 are the same
#

vt_arg0=$(basename $0)
vt_structs="vnd_ioc_attach_t vnd_ioc_link_t vnd_ioc_unlink_t"
vt_structs="$vt_structs vnd_ioc_nonblock_t vnd_ioc_buf_t vnd_ioc_info_t"

vt_t32="/tmp/vnd.iocsize.32.$$"
vt_t64="/tmp/vnd.iocsize.64.$$"

function fatal
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "$vt_arg0: $msg" >&2
	exit 1
}

function dump_types
{
	typeset file=$1
	typeset lib=$2
	typeset t

	for t in $vn_structs; do
		mdb -e \'::print -at $t\' $lib >> $file || fatal \
		    "failed to dump type $t from $lib"
	done
}

rm -f $vt_t32 $vt_t64 || fatal "failed to cleanup old temp files"
touch $vt_t32 $vt_t64 || fatal "failed to create temp files"

dump_types $vt_t32 /usr/lib/libvnd.so.1
dump_types $vt_t64 /usr/lib/64/libvnd.so.1

diff $vt_t32 $vt_t64
