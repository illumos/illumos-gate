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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fm/protocol.h>

#include <strings.h>
#include <libgen.h>

#include <fmd_log_impl.h>
#include <fmd_log.h>

/*ARGSUSED*/
int
fmd_log_filter_class(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	return (gmatch(rp->rec_class, arg));
}

/*ARGSUSED*/
int
fmd_log_filter_uuid(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	char *uuid;

	/*
	 * Note: the uuid filter matches *any* member whose name is 'uuid'.
	 * This permits us to match not only a list.suspect uuid but any
	 * other event that decides to embed uuids, too, using the same name.
	 */
	return (nvlist_lookup_string(rp->rec_nvl,
	    "uuid", &uuid) == 0 && strcmp(uuid, arg) == 0);
}

/*ARGSUSED*/
int
fmd_log_filter_before(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	uint64_t sec = ((struct timeval *)arg)->tv_sec;
	uint64_t nsec = ((struct timeval *)arg)->tv_usec * (NANOSEC / MICROSEC);
	return (rp->rec_sec == sec ? rp->rec_nsec <= nsec : rp->rec_sec <= sec);
}

/*ARGSUSED*/
int
fmd_log_filter_after(fmd_log_t *lp, const fmd_log_record_t *rp, void *arg)
{
	uint64_t sec = ((struct timeval *)arg)->tv_sec;
	uint64_t nsec = ((struct timeval *)arg)->tv_usec * (NANOSEC / MICROSEC);
	return (rp->rec_sec == sec ? rp->rec_nsec >= nsec : rp->rec_sec >= sec);
}
