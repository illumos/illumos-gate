#!/sbin/sh
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

DEFAULT_FILE="/etc/default/sendmail"
SENDMAIL="/usr/lib/smtp/sendmail/sendmail"
PATH="/usr/bin:/usr/sbin:/usr/ccs/bin"
export PATH

check_queue_interval_syntax()
{
	default="15m"
	if [ $# -lt 1 ]; then
		answer=$default
		return
	fi
	if echo $1 | egrep '^([0-9]*[1-9][0-9]*[smhdw])+$' >/dev/null 2>&1; then
		answer=$1
	else
		answer=$default
	fi
}

check_and_kill()
{
	PID=`head -1 $1`
	kill -0 $PID > /dev/null 2>&1
	[ $? -eq 0 ] && kill $PID
}

exist_or_exit()
{
	if [ ! -f $1 ]; then
		echo "$1 does not exist" >&2
		exit $SMF_EXIT_ERR_CONFIG
	fi
}

turn_m4_crank()
{
	# expected to be called with two arguments: .cf path & path to m4 file
	[ $# -lt 2 ] && return
	cf_path=$1
	m4_path=$2
	if [ "$m4_path" = "_DONT_TOUCH_THIS" ]; then
		if [ -f "${cf_path}.old" ]; then
			mv "$cf_path" "${cf_path}.new"
			[ $? -ne 0 ] && exit $SMF_EXIT_ERR_CONFIG
			mv "${cf_path}.old" "$cf_path"
			[ $? -ne 0 ] && exit $SMF_EXIT_ERR_CONFIG
		fi
		#
		# If ${cf_path}.old does not exist, assume it was taken care
		# of on a previous run.
		#
	else
		case "$m4_path" in
		/*)	;;	# absolute path
		*)	return;;
		esac
		exist_or_exit "$m4_path"
		cd `dirname "$m4_path"`
		base=`basename "$m4_path"`
		name=`basename "$m4_path" .mc`
		info=`svcprop -p config/include_info $SMF_FMRI 2>/dev/null`
		if [ "$info" = "true" ]; then
			m4flags=""
		else
			m4flags="-DSUN_HIDE_INTERNAL_DETAILS"
		fi
		m4 $m4flags /etc/mail/cf/m4/cf.m4 "$base" > "${name}.cf"
		[ $? -ne 0 ] && exit $SMF_EXIT_ERR_CONFIG
		cmp -s "${name}.cf" "$cf_path" || (
			cp "${name}.cf" "${cf_path}.tmp" &&
			chown root:bin "${cf_path}.tmp" &&
			chmod 444 "${cf_path}.tmp" &&
			mv "${cf_path}.tmp" "$cf_path"
		)
		[ $? -ne 0 ] && exit $SMF_EXIT_ERR_CONFIG
	fi
}
