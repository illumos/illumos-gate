divert(-1)
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Select the appropriate type of output format based on whether -Djava is set
# on the command line
ifdef(`java', `define(defdef, `    public static final String	$1 = "$1";')', `define(defdef, `defint($1,"$1")')')
ifdef(`java', `define(defstr, `    public static final String	$1 = $2;')', `define(defstr, `defint($1,$2)')')
ifdef(`java', `define(defint, `    public static final int	$1 = $2;')', `define(defint, `#define	$1	$2')')
# End of opening definitions; everything after next line is going in the output
divert(0)dnl
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This include file is generated from a m4 source file. Do not
 * modify this file.
 */

ifdef(`java', `package com.sun.dhcpmgr.data;
', `#ifndef _DHCP_SVC_CONFKEY_H
#define	_DHCP_SVC_CONFKEY_H

#pragma ident	"%Z'`%%'`M%	%'`I%	%'`E% SMI"')
ifdef(`java', `/**
 * DHCP server configuration parameters.
 */
public interface DhcpConfigOpts {', `
#ifdef	__cplusplus')
ifdef(`java', `dnl', extern "C" {)
ifdef(`java', `dnl', `#endif
')
/* Definitions for valid config file parameters */
defstr(DSVC_CK_DAEMON_ENABLED, "DAEMON_ENABLED")
defstr(DSVC_CK_RUN_MODE, "RUN_MODE")
defstr(DSVC_CK_VERBOSE, "VERBOSE")
defstr(DSVC_CK_RELAY_HOPS, "RELAY_HOPS")
defstr(DSVC_CK_INTERFACES, "INTERFACES")
defstr(DSVC_CK_ICMP_VERIFY, "ICMP_VERIFY")
defstr(DSVC_CK_OFFER_CACHE_TIMEOUT, "OFFER_CACHE_TIMEOUT")
defstr(DSVC_CK_RESCAN_INTERVAL, "RESCAN_INTERVAL")
defstr(DSVC_CK_LOGGING_FACILITY, "LOGGING_FACILITY")
defstr(DSVC_CK_BOOTP_COMPAT, "BOOTP_COMPAT")
defstr(DSVC_CK_RELAY_DESTINATIONS, "RELAY_DESTINATIONS")
defstr(DSVC_CK_RESOURCE, "RESOURCE")
defstr(DSVC_CK_RESOURCE_CONFIG, "RESOURCE_CONFIG")
defstr(DSVC_CK_NSU_TIMEOUT, "UPDATE_TIMEOUT")
defstr(DSVC_CK_PATH, "PATH")
defstr(DSVC_CK_CONVER, "CONVER")
defstr(DSVC_CK_HOSTS_RESOURCE, "HOSTS_RESOURCE")
defstr(DSVC_CK_HOSTS_DOMAIN, "HOSTS_DOMAIN")
defstr(DSVC_CK_MAX_THREADS, "MAX_THREADS")
defstr(DSVC_CK_MAX_CLIENTS, "MAX_CLIENTS")
defstr(DSVC_CK_LEASE_MIN_LRU, "LEASE_MIN_LRU")
defstr(DSVC_CK_CACHE_TIMEOUT, "CACHE_TIMEOUT")
defstr(DSVC_CK_RENOG_INTERVAL, "SECONDARY_SERVER_TIMEOUT")
defstr(DSVC_CK_OWNER_IP, "OWNER_IP")

/* Definitions for DEBUG config file parameters */
defstr(DSVC_CK_DBG_PORT_OFFSET, "DEBUG_PORT_OFFSET")
defstr(DSVC_CK_DBG_MEMORY_NET, "DEBUG_MEMORY_NET")

/* Definitions for valid HOSTS_RESOURCE settings */
defstr(DSVC_CV_NISPLUS, "nisplus")
defstr(DSVC_CV_FILES, "files")
defstr(DSVC_CV_DNS, "dns")

/* Definitions for valid BOOTP_COMPAT settings */
defstr(DSVC_CV_AUTOMATIC, "automatic")
defstr(DSVC_CV_MANUAL, "manual")

/* Definitions for valid LOGGING_FACILITY settings */
defint(DSVC_CV_LOGGING_FACILITY_MIN, 0)
defint(DSVC_CV_LOGGING_FACILITY_MAX, 7)

/* Definitions for valid RUN_MODE settings */
defstr(DSVC_CV_RELAY, "relay")
defstr(DSVC_CV_SERVER, "server")

/* Definitions for valid boolean values */
defstr(DSVC_CV_TRUE, "TRUE")
defstr(DSVC_CV_FALSE, "FALSE")

/* Definitions for server config for unspecified options */
defint(DSVC_CV_HOPS, 4)
defint(DSVC_CV_OFFER_TTL, 10)
defint(DSVC_CV_CACHE_TTL, 10)
defint(DSVC_CV_NSU_TO, 15)
defint(DSVC_CV_MIN_LRU, 60)
defint(DSVC_CV_RENOG_INT, 20)

/* Definitions for server config for DEBUG options */
defint(DSVC_CV_DBG_PORT_OFFSET, 0)
ifdef(`java', `dnl', `
#ifdef	__cplusplus')
}
ifdef(`java', `dnl', `#endif
')
ifdef(`java', `dnl', `#endif	/* !_DHCP_SVC_CONFKEY_H */')
