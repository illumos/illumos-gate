/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_EVENT_H
#define	_EMLXS_EVENT_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Define the actual driver events */
#include <emlxs_events.h>

#define	MAX_LOG_INFO_LENGTH	96

typedef struct emlxs_event_entry
{
	struct emlxs_event_entry	*next;
	struct emlxs_event_entry	*prev;

	uint32_t	id;
	uint32_t	timestamp;
	uint32_t	timer;

	emlxs_event_t	*evt;

	void *port;

	void		*bp;			/* Context buffer */
						/* pointer */
	uint32_t	size;			/* Context buffer */
						/* size */
	uint32_t	flag;
#define	EMLXS_DFC_EVENT_DONE	0x00000001
#define	EMLXS_SD_EVENT_DONE	0x00000002

} emlxs_event_entry_t;


typedef struct emlxs_event_queue
{
	kmutex_t		lock;
	kcondvar_t		lock_cv;

	uint32_t		last_id[32]; /* per event */
	uint32_t		next_id;
	uint32_t		count;

	emlxs_event_entry_t	*first;
	emlxs_event_entry_t	*last;

} emlxs_event_queue_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_EVENT_H */
