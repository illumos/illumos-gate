#!/bin/sh
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# ident	"%Z%%M%	%I%	%E% SMI"

DT_CHANGED=0

LOG_FMRI=svc:/system/system-log
CMSD_FMRI=svc:/network/rpc/cde-calendar-manager
BIND_FMRI=svc:/network/rpc/bind
XSERVER_FMRI=svc:/application/x11/x11-server
SENDMAIL_FMRI=svc:/network/smtp:sendmail
PRINTSERVER_FMRI=svc:/application/print/server
RFC1179_FMRI=svc:/application/print/rfc1179
CUPSSERVER_FMRI=svc:/application/cups/scheduler
CUPSRFC1179_FMRI=svc:/application/cups/in-lpd
IPPLISTENER_FMRI=svc:/application/print/ipp-listener
TTDB_FMRI=svc:/network/rpc/cde-ttdbserver
DTLOGIN_FMRI=svc:/application/graphical-login/cde-login
WEBCONSOLE_FMRI=svc:/system/webconsole
SMCWBEM_FMRI=svc:/application/management/wbem

usage()
{
	prog=`basename $0`
	echo "$prog: usage: $prog [ open | limited ]" >&2
	exit 2
}

#
# set_property fmri group property value
#
# sets the specified property in the specified property-group, creating
# the group and or property if necessary.
#
set_property()
{
	fmri=$1
	group=$2
	prop=$3
	val=$4

	if svcprop -qp $group $fmri; then :; else
		if svccfg -s $fmri addpg $group application; then :; else
			echo "Failed to create property group \"$group\" \c"
			echo "for $fmri."
			exit 1
		fi
	fi

	if svccfg -s $fmri setprop $group/$prop = boolean: $val; then :; else
		echo "Failed to set property $group/$prop for $fmri"
		exit 1
	fi
}

set_system_log()
{
	svcprop -q $LOG_FMRI || return 
	if [ "$1" = "local" ]; then
		val=false
	else
		val=true
	fi

	set_property $LOG_FMRI config log_from_remote $val
	svcadm refresh $LOG_FMRI
}

set_cmsd()
{
	svcprop -q $CMSD_FMRI:default || return
	if [ "$1" = "local" ]; then
		proto="ticlts"
	else
		proto="udp"
	fi

	inetadm -m $CMSD_FMRI:default proto=$proto
	svcadm refresh $CMSD_FMRI:default
}

set_rpcbind()
{
	svcprop -q $BIND_FMRI || return
	if [ "$1" = "local" ]; then
		val=true
	else
		val=false
	fi

	set_property $BIND_FMRI config local_only $val
	svcadm refresh $BIND_FMRI
}

set_xserver() {
	svcprop -q $XSERVER_FMRI || return
	if [ "$1" = "local" ]; then
		val=false
	else
		val=true
	fi

	set_property $XSERVER_FMRI options tcp_listen $val
	# don't need refresh since x11-server is not an actual service
}

set_sendmail()
{
	svcprop -q $SENDMAIL_FMRI || return
	if [ "$1" = "local" ]; then
		val=true
	else
		val=false
	fi

	set_property $SENDMAIL_FMRI config local_only $val
	svcadm refresh $SENDMAIL_FMRI
}

set_ttdbserver()
{
	svcprop -q $TTDB_FMRI:tcp || return
	if [ "$1" = "local" ]; then
		val=ticotsord
	else
		val=tcp
	fi
	inetadm -m $TTDB_FMRI:tcp proto="$val"
	svcadm refresh $TTDB_FMRI:tcp
}

set_dtlogin()
{
	svcprop -q $DTLOGIN_FMRI || return

	eval args=`svcprop -p dtlogin/args $DTLOGIN_FMRI`

	if echo $args | egrep -s udpPort 
	then
		old_port=`echo $args |
		    sed 's/.*-udpPort [ ]*\([0-9][0-9]*\).*/\1/'`
		new_args=`echo $args |
		    sed 's/\(.*\)-udpPort [0-9][0-9]*\(.*\)/\1\2/'`
	else
		old_port=-1
		new_args=$args
	fi

	if [ "$1" = "local" ]; then
		args="$new_args -udpPort 0"
		DT_CHANGED=1
	else
		# remove '-udpPort 0' argument. Leave intact if port != 0.
		if [ $old_port -eq 0 ]; then
			args="$new_args"
			DT_CHANGED=1
		fi
	fi

	svccfg -s $DTLOGIN_FMRI setprop dtlogin/args = "\"$args\""
	svcadm refresh $DTLOGIN_FMRI
}

set_webconsole() {
	svcprop -q $WEBCONSOLE_FMRI:console || return
	if [ "$1" = "local" ]; then
		val=false
	else
		val=true
	fi

	set_property $WEBCONSOLE_FMRI options tcp_listen $val
	svcadm refresh $WEBCONSOLE_FMRI
}

set_smcwbem() {
	svcprop -q $SMCWBEM_FMRI:default || return
	if [ "$1" = "local" ]; then
		val=false
	else
		val=true
	fi

	set_property $SMCWBEM_FMRI options tcp_listen $val
	svcadm refresh $SMCWBEM_FMRI
}

set_printing() {
	use_cups=`svcprop -C -p general/active $CUPSSERVER_FMRI:default \
		  2>/dev/null`

	case "$1" in
	"open")
		cups_options="--remote-admin --remote-printers"
		cups_options="$cups_options --share-printers --remote-any"
		svc_operation="enable"
		;;
	"local")
		cups_options="--no-remote-admin --no-remote-printers"
		cups_options="$cups_options --no-share-printers --no-remote-any"
		svc_operation="disable"
		;;
	esac

	case "$use_cups" in
	"true")
		if [ -x /usr/sbin/cupsctl ] ; then
			# only run cupsctl with elevated privilege to avoid
			# being prompted for a password
			[ `/usr/bin/id -u` = 0 ] && 
				/usr/sbin/cupsctl $cups_options
		fi
		svcadm $svc_operation $CUPSRFC1179_FMRI
		;;
	*)
		if [ "`svcprop -p restarter/state $PRINTSERVER_FMRI:default`" \
		     != "disabled" ] ; then
			svcadm $svc_operation $RFC1179_FMRI:default
			svcadm $svc_operation $IPPLISTENER_FMRI:default
		fi
		;;
	esac
}

if [ $# -ne 1 ]; then
	usage
fi

case $1 in
	"open")
		profile=generic_open.xml
		keyword="open"
		;;
	"limited")
		profile=generic_limited_net.xml
		keyword="local"
		;;
	*)
		usage
		;;
esac

if [ ! -f /var/svc/profile/$profile ]; then
	echo "/var/svc/profile/$profile nonexistent. Exiting."
	exit 1
fi

#
# set services
#
set_system_log $keyword
set_cmsd $keyword
set_rpcbind $keyword
set_xserver $keyword
set_sendmail $keyword
set_ttdbserver $keyword
set_dtlogin $keyword
set_webconsole $keyword
set_smcwbem $keyword
set_printing $keyword

#
# put the new profile into place, and apply it
#
ln -sf ./$profile /var/svc/profile/generic.xml
svccfg apply /var/svc/profile/generic.xml
if [ $profile = "generic_open.xml" ]
then
	# generic_open may not start inetd services on upgraded systems
	svccfg apply /var/svc/profile/inetd_generic.xml
fi

#
# Make the services aware of the new property values
#
if [ "`svcprop -p restarter/state $LOG_FMRI:default`" = "online" ]
then
	# need restart since refresh won't reread properties
	echo "restarting syslogd"
	svcadm restart $LOG_FMRI:default
fi

if [ "`svcprop -p restarter/state $SENDMAIL_FMRI`" = "online" ]
then
	# need restart since refresh won't pick up new command-line
	echo "restarting sendmail"
	svcadm restart $SENDMAIL_FMRI
fi

if [ "`svcprop -p restarter/state $SMCWBEM_FMRI:default`" = "online" ]
then
	# need restart since refresh won't pick up new command-line
	echo "restarting wbem"
	svcadm restart $SMCWBEM_FMRI:default
fi

if [ $DT_CHANGED -eq 1 ]; then
	if [ "`svcprop -p restarter/state $DTLOGIN_FMRI:default`" = "online" ]
	then
		r="y"
		if tty -s ; then
			printf \
			    "dtlogin needs to be restarted. Restart now? [Y] "
			read r
		fi
		if [ "$r" = "" -o "$r" = "y" -o "$r" = "Y" ]; then
			# Make sure we survive killing dtlogin...
			trap "" 15
			svcadm restart $DTLOGIN_FMRI 
			echo "restarting dtlogin"
		else
			printf "dtlogin not restarted. "
			printf "Restart it to put it in ${keyword}-mode.\n"
		fi
	fi
fi
