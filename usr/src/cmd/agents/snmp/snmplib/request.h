/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the 
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _REQUEST_H_
#define _REQUEST_H_

#include <sys/types.h>

/***** GLOBAL VARIABLES *****/

extern Oid sysUptime_name;
extern Oid sysUptime_instance;


/***** GLOBAL FUNCTIONS *****/

extern int32_t request_sysUpTime(char *error_label, char *community_name);
extern int request_snmpEnableAuthTraps(char *error_label);
extern SNMP_pdu *request_create(char *community, int type, char *error_label);
extern SNMP_pdu *request_send_blocking(IPAddress *ip_address, SNMP_pdu *request, char *error_label);
extern SNMP_pdu *request_send_to_port_blocking(IPAddress *ip_address, int port,SNMP_pdu *request, char *error_label);
extern SNMP_pdu *request_send_to_port_time_out_blocking(IPAddress *ip_address, int port,struct timeval *timeout,SNMP_pdu *request, char *error_label);

#endif
