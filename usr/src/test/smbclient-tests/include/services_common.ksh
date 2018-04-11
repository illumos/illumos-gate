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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
#

#
# NAME
#	service_enable
#
# DESCRIPTION
#	Enable service
#
# RETURN
#	0 - enabled service
#	1 - failed to enable service
#
service_enable () {
	smf=$1

	status=$(svcprop -p restarter/state $smf)
	if [[ $status == "online" ]]; then
		cti_report "service '$smf' is already enabled"
		return 0
	fi

	svcadm enable -rs $smf
}

#
# NAME
#	service_disable
#
# DESCRIPTION
#	Disable service
#
# RETURN
#	0 - disabled service
#	1 - failed to disable service
#
service_disable () {
	smf=$1

	status=$(svcprop -p restarter/state $smf)
	if [[ $status == "disabled" ]]; then
		cti_report "PASS: service '$smf' is already disabled"
		return 0
	fi
	svcadm disable -s $smf
}

#
# NAME
#	service_restart
#
# DESCRIPTION
#	Restart service
#
# RETURN
#	0 - restarted service
#	1 - failed to restart service
#
service_restart () {
	smf=$1

	svcadm restart $smf
}
