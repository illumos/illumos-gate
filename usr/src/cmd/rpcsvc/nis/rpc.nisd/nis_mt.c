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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/time.h>
#include <sys/types.h>
#include <errno.h>
#include <malloc.h>
#include <syslog.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "nis_proc.h"

DECLRWLOCK(upd_list);
DECLRWLOCK(ping_list);
DECLRWLOCK(nisopstats);
DECLRWLOCK(table_cache);
DECLRWLOCK(dircachestats);
DECLRWLOCK(translog);

extern void	check_updaters(void);
extern void	check_pingers(void);

/*
 * We replace the __start_clock() and __stop_clock() functons from libnsl
 * with our own versions that provide per-thread clocks.
 */
int
__start_clock(int clk) {
	nis_tsd_t	*tsd;
	if ((clk >= MAXCLOCKS) || (clk < 0) ||
			((tsd = __nis_get_tsd())->clocks[clk].tv_sec))
		return (FALSE);

	(void) gettimeofday(&(tsd->clocks[clk]), 0);
	return (TRUE);
}

uint32_t
__stop_clock(int clk) {
	struct timeval	now;
	uint32_t	secs, mics;
	nis_tsd_t	*tsd;

	if ((clk >= MAXCLOCKS) || (clk < 0) ||
			(!((tsd = __nis_get_tsd())->clocks[clk].tv_sec)))
		return (0);

	(void) gettimeofday(&now, 0);
	secs = (uint32_t)(now.tv_sec  - tsd->clocks[clk].tv_sec);
	mics = (uint32_t)(now.tv_usec - tsd->clocks[clk].tv_usec);
	if (mics < 0) {
		mics += 1000000;
		secs -= 1;
	}
	mics += 1000000*secs;
	tsd->clocks[clk].tv_sec = 0;
	return (mics);
}

static nis_tsd_t	nis_shared_tsd;
static pthread_key_t	nis_tsd_key;

void
__nis_tsd_destroy(void *key) {

	nis_tsd_t	*tsd = (nis_tsd_t *)key;
	cleanupblock_t	*rb, *next_rb;

	if (tsd != 0) {
		/* Free memory allocated by nis_get_static_storage() */
		if (tsd->censor_object_buf.buf != 0)
			free(tsd->censor_object_buf.buf);
		/* Purge loose ends */
		__nis_thread_cleanup(tsd);
		for (rb = tsd->ragblocks; rb != 0; rb = next_rb) {
			next_rb = rb->next;
#ifdef	NIS_MT_DEBUG
			printf("%d: 0x%x freed\n", pthread_self(), rb);
#endif	/* NIS_MT_DEBUG */
			free(rb);
		}
		free(tsd);
	}
}

int
__nis_init_tsd_key(void) {

	return (pthread_key_create(&nis_tsd_key, __nis_tsd_destroy));
}

#pragma init(__nis_init_tsd_key)

nis_tsd_t *
__nis_get_tsd(void) {
	nis_tsd_t	*tsd;

	if ((tsd = pthread_getspecific(nis_tsd_key)) == 0) {
		/* No TSD; create it */
		if ((tsd = malloc(sizeof (*tsd))) != 0) {
			/* Initialize TSD */
			memset(tsd, 0, sizeof (*tsd));
			/* Register TSD */
			if (pthread_setspecific(nis_tsd_key, tsd) != 0) {
				/* Can't store key; abort */
#ifdef	NIS_MT_DEBUG
				abort();
#endif	/* NIS_MT_DEBUG */
				free(tsd);
				tsd = &nis_shared_tsd;
			}
		} else {
			/* No memory ? */
#ifdef	NIS_MT_DEBUG
			abort();
#endif	/* NIS_MT_DEBUG */
			tsd = &nis_shared_tsd;
		}
	}

	return (tsd);
}

void
__nis_thread_cleanup(nis_tsd_t *tsd) {

	if (tsd->looseends != 0) {
		do_cleanup(tsd->looseends);
		tsd->looseends = 0;
	}
}
