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
 *
 * Copyright 1996 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

/*
 * HISTORY
 * 5-14-96	Jerry Yeung	add relay agent name
 * 6-18-96	Jerry Yeung	add pid file
 * 7-3-96	Jerry Yeung	add poll_interval & max_time_out
 */

#ifndef _DISPATCHER_H_
#define _DISPATCHER_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/***** GLOBAL CONTANTS *****/

/*
 *	the two modes of the SNMP Relay
 */

#define MODE_GROUP	1
#define MODE_SPLIT	2


/***** GLOBAL VARIABLES *****/

/*
 *	my IP address
 */

extern IPAddress my_ip_address;

extern char* relay_agent_name; /* (5-14-96) */

/*
 *	the socket descriptor on which we receive/send
 *	SNMP requests from/to the SNMP applications
 */

extern int clients_sd;


/*
 *	the socket descriptor on which we receive/send
 *	SNMP requests from/to the SNMP agents
 */

extern int agents_sd;

extern int trap_sd;
extern int relay_agent_trap_port;

/*
 * max_agent_time_out
 * poll_internval
 */
extern int relay_agent_max_agent_time_out;
extern int relay_agent_poll_interval;


/*
 *
 *	the name of the configuration directory
 */

extern char *config_dir;
extern char *pid_file;
extern char *resource_file;

/*
 *	the mode of the SNMP relay
 */

extern int mode;
extern int recovery_on;


#endif
