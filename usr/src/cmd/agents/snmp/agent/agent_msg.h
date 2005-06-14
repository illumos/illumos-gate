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
 * Copyright 1997 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _AGENT_MSG_H_
#define _AGENT_MSG_H_


/***** TRACING MESSAGES *****/

#define MSG_SIGHUP			"signal SIGHUP(%d) received"

#define MSG_READING_CONFIG		"re-reading its configuration file %s..."
#define MSG_CONFIG_READED		"...configuration re-read"


/***** SYSTEM ERRORS ****/

#define ERR_MSG_SOCKET			"socket() failed %s"
#define ERR_MSG_BIND			"bind() failed on UDP port %d %s"
#define ERR_MSG_SELECT			"select() failed %s"
#define ERR_MSG_FORK			"fork() failed %s"
#define ERR_MSG_FCLOSE			"fclose(%s) failed %s"
#define ERR_MSG_CHDIR			"chdir(%s) failed %s"
#define ERR_MSG_OPEN			"can't open config file %s %s"
#define ERR_MSG_FSTAT			"can't stat config file %s %s"
#define ERR_MSG_MMAP			"can't mmap config file %s %s"
#define ERR_MSG_MUNMAP			"munmap() failed %s"
#define ERR_MSG_CLOSE			"close() failed %s"


/***** PDU RELATED ERRORS *****/

#define ERR_MSG_PDU_RECEIVED		"error while receiving a pdu from %s: %s"
#define ERR_MSG_PDU_PROCESS		"unable to process a pdu from %s"
#define ERR_MSG_SNMP_ERROR		"SNMP error (%s, %lu) sent back to %s"
#define ERR_MSG_PDU_SEND		"error while sending a pdu back to %s: %s"


/***** MISCELLANEOUS *****/

#define ERR_MSG_ALLOC			"cannot allocate memory" 

#define ERR_MSG_MANAGER_DUP		"the manager %s already exists"
#define ERR_MSG_COMMUNITY_DUP		"the community %s already exists"

#define ERR_MSG_MY_IP_ADDRESS           "unable to get my IP address: %s"
 
#define ERR_MSG_VARBIND_LIMIT           "unable to handle SNMP request with more than 32 variables"
 
#define ERR_MSG_UNKNOWN_FRAGMENT        "unknown PDU fragment received from agent %s (%s)"
#define ERR_MSG_AGENT_NOT_RESPONDING    "agent %s not responding"
 

#endif
