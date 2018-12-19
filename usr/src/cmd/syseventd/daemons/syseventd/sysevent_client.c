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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * syseventd client interfaces
 */

#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <door.h>
#include <errno.h>
#include <strings.h>
#include <thread.h>
#include <pthread.h>
#include <synch.h>
#include <syslog.h>
#include <fcntl.h>
#include <stropts.h>
#include <locale.h>
#include <libsysevent.h>
#include <sys/stat.h>
#include <sys/sysevent.h>

#include "syseventd.h"
#include "message.h"

/*
 * sysevent_client.c - contains routines particular to syseventd client
 *			management (addition and deletion).
 */

/* Global client table and lock */
struct sysevent_client *sysevent_client_tbl[MAX_SLM];
mutex_t client_tbl_lock;

/*
 * initialize_client_tbl - Initialize each client entry in the syseventd
 *			   client table.  Each entry in the client table
 *			   entry represents one shared-object (SLM) client.
 */
void
initialize_client_tbl()
{
	struct sysevent_client	*scp;
	int 			i;

	for (i = 0; i < MAX_SLM; ++i) {
		if ((scp = (struct sysevent_client *)malloc(
			sizeof (struct sysevent_client))) == NULL)
			goto init_error;

		if (mutex_init(&scp->client_lock, USYNC_THREAD, NULL) != 0)
			goto init_error;

		scp->client_data = NULL;
		scp->client_num = i;
		scp->eventq = NULL;

		/* Clear all flags when setting UNLOADED */
		scp->client_flags = SE_CLIENT_UNLOADED;

		sysevent_client_tbl[i] = scp;
	}

	return;

init_error:
	syseventd_err_print(INIT_CLIENT_TBL_ERR);
	syseventd_exit(1);
}

/*
 * insert_client - called when a new SLM is loaded with syseventd.  The
 *		   client specific data is updated to reflect this addition
 */
int
insert_client(void *client_data, int client_type, int retry_limit)
{
	int	i;
	struct sysevent_client	*scp;

	(void) mutex_lock(&client_tbl_lock);
	for (i = 0; i < MAX_SLM; ++i) {
		scp = sysevent_client_tbl[i];
		if (scp->client_data == NULL) {
			(void) mutex_lock(&scp->client_lock);
			scp->client_data = client_data;
			scp->client_type = client_type;
			scp->retry_limit = retry_limit;
			scp->client_flags |= SE_CLIENT_LOADED;
			(void) cond_init(&scp->client_cv, USYNC_THREAD,
				NULL);
			(void) mutex_unlock(&scp->client_lock);
			(void) mutex_unlock(&client_tbl_lock);
			return (i);
		}
	}

	(void) mutex_unlock(&client_tbl_lock);
	syseventd_print(1, "Unable to insert into syseventd client table\n");
	return (-1);
}

/*
 * delete_client - called to remove an SLM from the client table.  Client
 *		   removal may occur when syseventd terminates, receives
 *		   a SIGHUP or the client must be force unloaded due
 *		   it's unresponsive nature.
 */
void
delete_client(int id)
{
	struct sysevent_client	*scp;

	scp = sysevent_client_tbl[id];

	free(scp->client_data);
	scp->client_data = NULL;

	/* Clear all flags when setting UNLOADED */
	scp->client_flags = SE_CLIENT_UNLOADED;
	(void) cond_destroy(&scp->client_cv);
	bzero(&scp->client_cv, sizeof (cond_t));
}
