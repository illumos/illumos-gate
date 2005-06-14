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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PROTOCOL_H
#define	_PROTOCOL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <startd.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	GRAPH_UPDATE_RELOAD_GRAPH,
	GRAPH_UPDATE_ADD_INSTANCE,
	GRAPH_UPDATE_STATE_CHANGE
} graph_event_type_t;

typedef struct protocol_states {
	restarter_instance_state_t	ps_state;
	restarter_instance_state_t	ps_state_next;
	restarter_error_t		ps_err;
} protocol_states_t;


typedef struct graph_protocol_event {
	char			*gpe_inst;
	size_t			gpe_inst_sz;
	graph_event_type_t	gpe_type;
	protocol_states_t	*gpe_data;

	uu_list_node_t		gpe_link;
	pthread_mutex_t		gpe_lock;
} graph_protocol_event_t;

typedef struct graph_update {
	pthread_mutex_t			gu_lock;
	pthread_cond_t			gu_cv;
	int				gu_wakeup;

	pthread_mutex_t			gu_freeze_lock;
	pthread_cond_t			gu_freeze_cv;
	int				gu_freeze_wakeup;
} graph_update_t;

typedef struct restarter_protocol_event {
	char			*rpe_inst;
	restarter_event_type_t	rpe_type;

	uu_list_node_t		rpe_link;
} restarter_protocol_event_t;

typedef struct restarter_update {
	pthread_mutex_t			restarter_update_lock;
	pthread_cond_t			restarter_update_cv;
	int				restarter_update_wakeup;
} restarter_update_t;

extern restarter_update_t *ru;
extern graph_update_t *gu;

void graph_protocol_init();
void graph_protocol_send_event(const char *, graph_event_type_t,
    protocol_states_t *);
graph_protocol_event_t *graph_event_dequeue();
void graph_event_requeue(graph_protocol_event_t *);
void graph_event_release(graph_protocol_event_t *);

void restarter_protocol_init();
evchan_t *restarter_protocol_init_delegate(char *);
void restarter_protocol_send_event(const char *, evchan_t *,
    restarter_event_type_t);
restarter_protocol_event_t *restarter_event_dequeue();
void restarter_event_requeue(restarter_protocol_event_t *);
void restarter_event_release(restarter_protocol_event_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PROTOCOL_H */
