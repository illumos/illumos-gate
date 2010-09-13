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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include "filebench.h"
#include "multi_client_sync.h"
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define	MCS_NAMELENGTH	128
#define	MCS_MSGLENGTH	(MCS_NAMELENGTH * 8)

static int mc_sync_sock_id;
static char this_client_name[MCS_NAMELENGTH];

/*
 * Open a socket to the master synchronization host
 */
int
mc_sync_open_sock(char *master_name, int master_port, char *my_name)
{
	struct sockaddr_in client_in;
	struct sockaddr_in master_in;
	struct hostent master_info;
	int error_num;
	char buffer[MCS_MSGLENGTH];

	(void) strncpy(this_client_name, my_name, MCS_NAMELENGTH);
	if ((mc_sync_sock_id = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		filebench_log(LOG_ERROR, "could not create a client socket");
		return (FILEBENCH_ERROR);
	}

	client_in.sin_family = AF_INET;
	client_in.sin_port = INADDR_ANY;
	client_in.sin_addr.s_addr = INADDR_ANY;

	if (bind(mc_sync_sock_id, (struct sockaddr *)&client_in,
	    sizeof (client_in)) == -1) {
		filebench_log(LOG_ERROR, "could not bind to client socket");
		return (FILEBENCH_ERROR);
	}

	if (gethostbyname_r(master_name, &master_info, buffer, MCS_MSGLENGTH,
	    &error_num) == NULL) {
		filebench_log(LOG_ERROR, "could not locate sync master");
		return (FILEBENCH_ERROR);
	}

	master_in.sin_family = AF_INET;
	master_in.sin_port = htons((uint16_t)master_port);
	(void) memcpy(&master_in.sin_addr.s_addr, *master_info.h_addr_list,
	    sizeof (master_in.sin_addr.s_addr));

	if (connect(mc_sync_sock_id, (struct sockaddr *)&master_in,
	    sizeof (master_in)) == -1) {
		filebench_log(LOG_ERROR,
		    "connection refused to sync master, error %d", errno);
		return (FILEBENCH_ERROR);
	}

	return (FILEBENCH_OK);
}

/*
 * Send a synchronization message and wait for a reply
 */
int
mc_sync_synchronize(int sync_point)
{
	char msg[MCS_MSGLENGTH];
	int amnt;

	(void) snprintf(msg, MCS_MSGLENGTH,
	    "cmd=SYNC,id=xyzzy,name=%s,sample=%d\n",
	    this_client_name, sync_point);
	(void) send(mc_sync_sock_id, msg, strlen(msg), 0);

	amnt = 0;
	msg[0] = 0;

	while (strchr(msg, '\n') == NULL)
		amnt += recv(mc_sync_sock_id, msg, sizeof (msg), 0);

	filebench_log(LOG_INFO, "sync point %d succeeded!\n", sync_point);
	return (FILEBENCH_OK);
}
