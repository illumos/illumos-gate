/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_MSG_H
#define	_EMLXS_MSG_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Define the actual driver messages */
#include <emlxs_messages.h>

/* File identification numbers */
#define	EMLXS_MSG_DEF(_number)    static const uint32_t _FILENO_ = _number
#define	EMLXS_CLOCK_C		1
#define	EMLXS_DIAG_C		2
#define	EMLXS_DOWNLOAD_C	3
#define	EMLXS_ELS_C		4
#define	EMLXS_FCP_C		5
#define	EMLXS_HBA_C		6
#define	EMLXS_MBOX_C		7
#define	EMLXS_MEM_C		8
#define	EMLXS_NODE_C		9
#define	EMLXS_PKT_C		10
#define	EMLXS_SOLARIS_C		11
#define	EMLXS_MSG_C		12
#define	EMLXS_IP_C		13
#define	EMLXS_THREAD_C		14
#define	EMLXS_DFC_C		15
#define	EMLXS_DHCHAP_C		16
#define	EMLXS_FCT_C		17
#define	EMLXS_DUMP_C		18
#define	EMLXS_SLI3_C		19
#define	EMLXS_SLI4_C		20
#define	EMLXS_EVENT_C		21
#define	EMLXS_FCF_C		22

#define	EMLXS_CONTEXT		port, _FILENO_, __LINE__
#define	EMLXS_MSGF		emlxs_msg_printf

#ifdef EMLXS_DBG
#define	EMLXS_DEBUGF		emlxs_msg_printf
#else	/* EMLXS_DBG */
#define	EMLXS_DEBUGF
#endif	/* EMLXS_DBG */

#define	MAX_LOG_INFO_LENGTH	96

typedef struct emlxs_msg_entry
{
	uint32_t	id;				/* entry id  */
	clock_t		time;				/* timestamp */
	timespec_t	id_time;			/* high res timestamp */

	emlxs_msg_t	*msg;				/* Msg pointer */

	uint32_t	vpi;
	uint32_t	instance;			/* Adapter instance */
	uint32_t	fileno;				/* File number */
	uint32_t	line;				/* Line number */

	char		buffer[MAX_LOG_INFO_LENGTH];	/* Additional info */
							/* buffer */
} emlxs_msg_entry_t;


typedef struct emlxs_msg_log
{
	kmutex_t		lock;

	clock_t			start_time;
	uint32_t		instance;

	uint32_t		size;		/* Maximum entries in */
						/* circular buffer */
	uint32_t		count;		/* Total number of entries */
						/* recorded */
	uint32_t		next;		/* Next index into circular */
						/* buffer */
	uint32_t		repeat;		/* repeat counter */

	emlxs_msg_entry_t	*entry;		/* pointer to entry buffer */
} emlxs_msg_log_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_MSG_H */
