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
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# IPfilter's firewall
#
# routed and its siblings use ICMP Router Discovery protocol, simply allow
# these packets so the client portion of routed can work.
#
gen_IRDP_rules()
{
	# Allow incoming icmp from routers for successful discovery.
	# IRDP - ICMP type 9 and 10, advertisement and solicitation, respectively.
	#
	echo "pass in log quick proto icmp from any to any icmp-type 10" >>${1}
	echo "pass in log quick proto icmp from any to any icmp-type 9" >>${1}
}

#
# These functions are used to help map daemon arguments to appropriate
# routing properties and back, allowing legacy specifications of daemon
# arguments to be reflected in SMF property values for daemon services.
#

#
# set_routeadm_property inst_fmri propname propvalue
#
# Functions sets appropriate property value in routeadm property group
# (via routeadm -m) for inst_fmri to propvalue.
#
set_routeadm_property()
{
	/sbin/routeadm -m $1 ${2}="${3}"
}

#
# The functions below are used to map from daemon arguments to appropriate
# routeadm properties (properties that the service user can manipulate
# to control daemon functionality. getopts is used extensively to
# retrieve options/values from argument list, and these option values
# are used to set properties appropriately.
#

#
# set_daemon_value_property inst_fmri optstring options option prop
#	default_value
#
# Function looks for option/value in argument string, and sets associated
# property if found. If a default is specified, and the option is not
# in the argument string, it will be used.
#
set_daemon_value_property()
{
	OPTIND=1
	value_set=""
	while getopts $3 opt $2; do
		case $opt in
			"$4" )	set_routeadm_property $1 $5 $OPTARG
				value_set="true"
				;;
			? )
		esac
	done
	# No value set - use default if specified.
	if [ -z "$value_set" -a -n "$6" ]; then
		set_routeadm_property $1 $5 $6
	fi
}

#
# set_daemon_ordered_multivalue_property inst_fmri optstring options option prop
#       default_value
#
# Function looks for option/values in argument string, and sets associated
# property if found. If a default is specified, and the option is not
# in the argument string, it will be used.  Use ";" as delimiter for
# multiple values.
#
set_daemon_ordered_multivalue_property()
{
	OPTIND=1
	value_set=""
	while getopts $3 opt $2; do
		case $opt in
			"$4" )  if [ -z "$value_set" ]; then
					value_set="${OPTARG}"
				else
					value_set="$value_set;${OPTARG}"
				fi
                                ;;
			? )
		esac
	done
	if [ -n "$value_set" ]; then
		set_routeadm_property $1 $5 "$value_set"
	fi
	# No value set - use default if specified.
	if [ -z "$value_set" -a -n "$6" ]; then
		set_routeadm_property $1 $5 $6
	fi
}

#
# set_daemon_boolean_property inst_fmri optstring options option
#       prop value_if_found default
#
# Function looks for option in argument string, and sets associated
# property, if found, to value_if_found. If a default is specified, and
# the option is not found, it will be used.
#
set_daemon_boolean_property()
{
	OPTIND=1
	value_set=""
	while getopts $3 opt $2; do
		case $opt in
			"$4" )	set_routeadm_property $1 $5 $6
				value_set="true"
				;;
			? )
		esac
	done
	# No value set - use default if specified.
	if [ -z "$value_set" -a -n "$7" ]; then
		set_routeadm_property $1 $5 $7
	fi
}

#
# set_daemon_nonoption_properties inst_fmri optstring options propnames
#       default
#
# Function looks past option list for addition values, and sets properties
# specified in propnames to additional positional values. If no value
# is found for additional property, default is used.
#
set_daemon_nonoption_properties()
{
	OPTIND=1
	# Skip options
	while getopts $3 opt $2; do
		case $opt in
			? )
		esac
	done
	pos=$OPTIND
	for prop in $4
	do
		val=`/usr/bin/echo $2 | /usr/bin/nawk -v POS=$pos \
		    '{ print $POS }'`
		if [ -z "$val" ]; then
			val="$5"
		fi
		set_routeadm_property $1 $prop $val
		pos=`expr $pos + 1`
	done
}

#
# get_daemon_args $inst_fmri
#
# Retrieves routeadm/daemon-args property values, if any.  Removes
# quotes around values including spaces.
#
get_daemon_args()
{
	args=`/usr/sbin/svccfg -s $1 listprop routeadm/daemon-args | \
	    /usr/bin/nawk '{ for (i = 3; i <= NF; i++) printf "%s ", $i }' | \
	    /usr/bin/nawk '{sub(/^\"/, ""); sub(/\"[ \t]*$/,""); print}'`
	echo "$args"
}

#
# clear_daemon_args $inst_fmri
#
# Blanks routeadm/daemon-args property used in upgrade.
#
clear_daemon_args()
{
	/usr/sbin/svccfg -s $1 delprop routeadm/daemon-args 2>/dev/null
}

#
# The functions below are used to map back from property settings to
# commandline arguments to launch daemons.
#

get_routeadm_property()
{
	propval=`/sbin/routeadm -l $1 | /usr/bin/nawk -v PROP=$2 \
	    '($1 == PROP) { for (i = 3; i < NF; i++) printf $i" "; \
	    if (NF >= 3) {printf $NF}}'`
	echo "$propval"
}

#
# get_daemon_option_from_boolean_property inst_fmri prop option value_set
#
# Returns appropriate daemon option for boolean property prop - if current
# value matches value_set.
#
get_daemon_option_from_boolean_property()
{
	propval=`get_routeadm_property $1 $2`
	if [ "$propval" = "$4" ]; then
		echo "${3}"
	fi
}

#
# get_daemon_option_from_property inst_fmri prop option ignore_value
#
# Returns appropriate daemon option and associated value (unless value
# matches ignore_value, in which case nothing is returned).
#
get_daemon_option_from_property()
{
	propval=`get_routeadm_property $1 $2`
	if [ "$propval" != "$4" ]; then
		echo "-${3} $propval"
	fi
}

#
# get_daemon_ordered_multivalue_option_from_property inst_fmri prop
# option
#
# Returns appropriate daemon option and associated values. Values are
# unquoted, i.e. -A value1 -A value2
#
get_daemon_ordered_multivalue_option_from_property()
{
	# get property values, removing trailing delimiter.
	propvals=`get_routeadm_property $1 $2 | \
	    /usr/bin/nawk '{sub(/;[ \t]*$/, ""); print }'`
	# Substitute switch for internal delimiters.
	fixed_propvals=`/usr/bin/echo $propvals | \
	    /usr/bin/nawk -v SWITCH=" -${3} " \
	    '{sub(/;/, SWITCH); print }'`
	if [ -n "$fixed_propvals" ]; then
		echo "-${3} $fixed_propvals"
	fi
}

#
# get_nonoption_property inst_fmri prop ignore_value
#
# Returns appropriate non-option property (at end of option list), unless
# value matches ignore value, in which case nothing is returned.
#
get_daemon_nonoption_property()
{
	propval=`get_routeadm_property $1 $2`
	if [ -n "$propval" -a "$propval" != "$3" ]; then
		echo "$propval"
	fi
}
