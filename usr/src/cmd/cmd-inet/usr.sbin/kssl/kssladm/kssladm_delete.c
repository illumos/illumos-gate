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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <netinet/in.h> /* struct sockaddr_in */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <libscf.h>
#include <inet/kssl/kssl.h>
#include "kssladm.h"

void
usage_delete(boolean_t do_print)
{
	if (do_print)
		(void) fprintf(stderr, "Usage:\n");
	(void) fprintf(stderr,
	    "kssladm delete [-v] [<server_address>] <server_port>\n");
}

int
do_delete(int argc, char *argv[])
{
	struct sockaddr_in6 server_addr;
	char c;
	char *port, *addr;
	int pcnt;

	if (argc < 3) {
		goto err;
	}

	argc -= 1;
	argv += 1;

	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			verbose = B_TRUE;
			break;
		default:
			goto err;
		}
	}

	pcnt = argc - optind;
	if (pcnt == 1) {
		port = argv[optind];
		addr = NULL;
	} else if (pcnt == 2) {
		addr = argv[optind];
		port = argv[optind + 1];
	}

	if (parse_and_set_addr(addr, port, &server_addr) < 0) {
		goto err;
	}

	if (kssl_send_command((char *)&server_addr, KSSL_DELETE_ENTRY) < 0) {
		perror("Error deleting entry");
		return (FAILURE);
	}

	if (verbose)
		(void) printf("Successfully loaded cert and key\n");

	return (SUCCESS);

err:
	usage_delete(B_TRUE);
	return (SMF_EXIT_ERR_CONFIG);
}
