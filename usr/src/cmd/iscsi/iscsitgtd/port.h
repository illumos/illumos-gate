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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef PORT_H
#define	PORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "iscsi_conn.h"

typedef struct port_args {
	target_queue_t	*port_mgmtq, /* management queue */
			*port_dataq;	/* incoming data for thread */
	int		port_num, /* port number to monitor */
			port_socket;
} port_args_t;

void port_init();
void *port_watcher(void *v);
void *port_management(void *v);
void port_conn_remove(iscsi_conn_t *c);

extern iscsi_conn_t *conn_head;

#endif	/* PORT_H */
