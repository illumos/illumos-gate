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

/*
 * IPMP general interfaces (PSARC/2002/615).
 */

#include <assert.h>
#include <stdlib.h>
#include <locale.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "ipmp_impl.h"

/*
 * Allocate a handle and store it in `*handlep' upon success.  Returns an IPMP
 * error code.
 */
int
ipmp_open(ipmp_handle_t *handlep)
{
	ipmp_state_t	*statep;

	statep = malloc(sizeof (ipmp_state_t));
	if (statep == NULL)
		return (IPMP_ENOMEM);

	statep->st_fd = -1;
	statep->st_snap = NULL;
	statep->st_magic = IPMP_MAGIC;

	*handlep = statep;
	return (IPMP_SUCCESS);
}

/*
 * Destroy the IPMP handle named by `handle'.
 */
void
ipmp_close(ipmp_handle_t handle)
{
	ipmp_state_t	*statep = handle;

	/*
	 * If this assertion triggers, someone called ipmp_close() twice in
	 * a row or stomped on us.
	 */
	assert(statep->st_magic == IPMP_MAGIC);

	/*
	 * If this assertion triggers, something's gone wrong internally.
	 */
	assert(statep->st_fd == -1);

	if (statep->st_snap != NULL)
		ipmp_snap_free(statep->st_snap);

	statep->st_magic = 0;
	free(statep);
}

/*
 * Error messages; must be in the same order as the codes in <ipmp.h>
 */
static char *errmsgs[IPMP_NERR] = {
	"operation succeeded", 			/*  0 IPMP_SUCCESS	*/
	"operation failed",			/*  1 IPMP_FAILURE	*/
	"minimum failover redundancy not met",	/*  2 IPMP_EMINRED	*/
	"failback disabled",			/*  3 IPMP_EFBDISABLED  */
	"unknown IPMP data address", 		/*  4 IPMP_EUNKADDR	*/
	"invalid argument",			/*  5 IPMP_EINVAL	*/
	"out of memory",			/*  6 IPMP_ENOMEM	*/
	"cannot contact in.mpathd",		/*  7 IPMP_ENOMPATHD	*/
	"unknown IPMP group", 			/*  8 IPMP_EUNKGROUP	*/
	"interface is not using IPMP",		/*  9 IPMP_EUNKIF	*/
	"unable to communicate with in.mpathd",	/* 10 IPMP_EPROTO	*/
	"interface has duplicate hardware address"
						/* 11 IPMP_EHWADDRDUP	*/
};

/*
 * Return a string describing the IPMP error code named by `error'.
 */
const char *
ipmp_errmsg(int error)
{
	if (error >= IPMP_NERR || error < 0)
		return (dgettext(TEXT_DOMAIN, "<unknown error>"));

	if (error == IPMP_FAILURE)
		return (strerror(errno));

	return (dgettext(TEXT_DOMAIN, errmsgs[error]));
}
