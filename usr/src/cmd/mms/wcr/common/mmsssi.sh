#!/bin/csh -f
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

#
# This script is used by the watcher daemon to keep a copy of ssi running.
# If this script exits, the daemon will start another.  If the site
# for whatever reason, has its own version of ssi, then this script
# should be modified to wait for a SIGTERM signal and then exit.  SIGTERM is
# the signal sent by the daemon to stop the process.
#
#

/usr/sbin/ping ${CSI_HOSTNAME} >&! /dev/null
if ( $status != "0" ) then
	echo "ACSLS server ${CSI_HOSTNAME} IS UNPINGABLE" >> /var/log/mms/wcr/wcr.debug
	exit 1
endif
#
#
setenv CSI_TCP_RPCSERVICE TRUE
setenv CSI_UDP_RPCSERVICE TRUE
setenv CSI_CONNECT_AGETIME 172800
setenv CSI_RETRY_TIMEOUT 4
setenv CSI_RETRY_TRIES 5
setenv ACSAPI_PACKET_VERSION 4
exec ${MMS_SSI_PATH}/ssi $1 ${ACSAPI_SSI_SOCKET} 23 ;
